import unittest

from vela.aggregator import Aggregator
from vela.asn import AsnDb
from vela.events import PacketEvent
from vela.sources.tls import SniExtractor, parse_client_hello

ME = "192.168.2.17"
GH = "140.82.112.3"


def client_hello(sni: str | None, pad: int = 0) -> bytes:
    """Build a minimal ClientHello record, field order per RFC 8446."""
    exts = b""
    if pad:  # padding extension placed before the SNI to push it into a second TCP segment
        exts += (21).to_bytes(2, "big") + pad.to_bytes(2, "big") + bytes(pad)
    if sni is not None:
        name = sni.encode()
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        body = len(entry).to_bytes(2, "big") + entry
        exts += (0).to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    hello = (
        b"\x03\x03" + bytes(32)              # client_version + random
        + b"\x00"                            # session_id
        + b"\x00\x02\x13\x01"                # cipher_suites: TLS_AES_128_GCM_SHA256
        + b"\x01\x00"                        # compression_methods: null
        + len(exts).to_bytes(2, "big") + exts
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def pkt(src, dst, sport=50000, dport=443, **kw):
    return PacketEvent(ts=0.0, src=src, dst=dst, l4="tcp", sport=sport, dport=dport, size=100, **kw)


class SniTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_client_hello(client_hello("GitHub.com")), "github.com")
        self.assertEqual(parse_client_hello(client_hello(None)), "")
        self.assertEqual(parse_client_hello(b"GET / HTTP/1.1\r\n"), "")
        self.assertIsNone(parse_client_hello(client_hello("github.com")[:40]))

    def test_reassembles_split_hello(self):
        data = client_hello("api.anthropic.com", pad=1500)
        x, key = SniExtractor(), ("a", 1, "b", 443)
        self.assertEqual(x.feed(key, data[:1460]), "")
        self.assertEqual(x.feed(key, data[1460:]), "api.anthropic.com")

    def test_ignores_non_hello_traffic(self):
        x = SniExtractor()
        self.assertEqual(x.feed(("a", 1, "b", 443), b"\x17\x03\x03\x00\x10" + bytes(16)), "")
        self.assertEqual(x._pending, {})


class AsnTest(unittest.TestCase):
    def setUp(self):
        self.db = AsnDb([
            ("1.0.1.0", "1.0.3.255", 0, "Not routed"),
            ("140.82.112.0", "140.82.112.255", 36459, "GITHUB"),
            ("2607:6bc0::", "2607:6bc0:0:ffff:ffff:ffff:ffff:ffff", 399358, "ANTHROPIC"),
        ])

    def test_lookup(self):
        self.assertEqual(self.db.lookup(GH), (36459, "GITHUB"))
        self.assertEqual(self.db.lookup("2607:6bc0::10"), (399358, "ANTHROPIC"))
        self.assertIsNone(self.db.lookup("140.82.113.1"))   # outside every range
        self.assertIsNone(self.db.lookup("1.0.2.1"))        # not announced
        self.assertIsNone(self.db.lookup("not-an-ip"))


class NamingPriorityTest(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator({ME}, asn_lookup=lambda ip: (36459, "GITHUB Inc") if ip == GH else None)

    def node(self, ts):
        return next(m for m in self.agg.flush(ts) if m["type"] == "node" and m["ip"] == GH)

    def test_asn_name_when_nothing_else(self):
        self.agg.add(pkt(ME, GH))
        n = self.node(1)
        self.assertEqual((n["name"], n["name_source"], n["asn"], n["org"]), ("GITHUB", "asn", "AS36459", "GITHUB Inc"))

    def test_sni_upgrades_asn_and_dns_upgrades_sni(self):
        self.agg.add(pkt(ME, GH))
        self.node(1)
        self.agg.add(pkt(ME, GH, sni="github.com"))
        self.assertEqual(self.node(2)["name_source"], "sni")
        self.agg.add(pkt(GH, ME, sport=53, dport=5353, dns_answers=((GH, "www.github.com"),)))
        n = self.node(3)
        self.assertEqual((n["name"], n["name_source"]), ("www.github.com", "dns"))

    def test_sni_does_not_override_dns(self):
        self.agg.add(pkt(GH, ME, sport=53, dport=5353, dns_answers=((GH, "github.com"),)))
        self.agg.add(pkt(ME, GH, sni="other.example"))
        n = self.node(1)
        self.assertEqual((n["name"], n["name_source"]), ("github.com", "dns"))


if __name__ == "__main__":
    unittest.main()
