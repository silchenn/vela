import unittest

from vela.aggregator import Aggregator, classify, service_port
from vela.events import PacketEvent

ME = "192.168.2.17"
GW = "192.168.2.1"
GH = "140.82.112.3"


def pkt(src, dst, l4="tcp", sport=50000, dport=443, size=100, **kw):
    return PacketEvent(ts=0.0, src=src, dst=dst, l4=l4, sport=sport, dport=dport, size=size, **kw)


class ClassifyTest(unittest.TestCase):
    def test_protocols(self):
        self.assertEqual(classify("tcp", 443), "https")
        self.assertEqual(classify("udp", 443), "quic")
        self.assertEqual(classify("tcp", 80), "http")
        self.assertEqual(classify("udp", 53), "dns")
        self.assertEqual(classify("tcp", 22), "other")

    def test_service_port(self):
        self.assertEqual(service_port(50000, 443), 443)
        self.assertEqual(service_port(443, 50000), 443)  # 本机做服务端
        self.assertEqual(service_port(50000, 22), 22)
        self.assertEqual(service_port(51000, 52000), 52000)


class AggregatorTest(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator({ME}, gateway=GW)

    def flows(self):
        return [m for m in self.agg.flush(1) if m["type"] == "flow"]

    def test_merges_both_directions_into_one_flow(self):
        self.agg.add(pkt(ME, GH, size=100))
        self.agg.add(pkt(GH, ME, sport=443, dport=50000, size=1500))
        self.agg.add(pkt(GH, ME, sport=443, dport=50000, size=1500))
        [flow] = self.flows()
        self.assertEqual((flow["src"], flow["dst"], flow["proto"], flow["port"]), (ME, GH, "https", 443))
        self.assertEqual((flow["bytes_up"], flow["bytes_down"]), (100, 3000))

    def test_flush_resets_window(self):
        self.agg.add(pkt(ME, GH))
        self.assertEqual(len(self.flows()), 1)
        self.assertEqual(self.flows(), [])

    def test_nodes_emitted_once_with_kinds(self):
        self.agg.add(pkt(ME, GH))
        self.agg.add(pkt(ME, GW, l4="udp", dport=53))
        nodes = {m["ip"]: m for m in self.agg.flush(1) if m["type"] == "node"}
        self.assertEqual(nodes[ME]["kind"], "local")
        self.assertEqual(nodes[GW]["kind"], "gateway")
        self.assertEqual(nodes[GH]["kind"], "external")
        self.agg.add(pkt(ME, GH))
        self.assertEqual([m for m in self.agg.flush(2) if m["type"] == "node"], [])

    def test_dns_names_external_nodes(self):
        self.agg.add(pkt(GW, ME, l4="udp", sport=53, dport=5353, dns_answers=((GH, "github.com"),)))
        self.agg.add(pkt(ME, GH))
        nodes = {m["ip"]: m for m in self.agg.flush(1) if m["type"] == "node"}
        self.assertEqual(nodes[GH]["name"], "github.com")

    def test_late_dns_answer_renames_node(self):
        self.agg.add(pkt(ME, GH))
        self.agg.flush(1)
        self.agg.add(pkt(GW, ME, l4="udp", sport=53, dport=5353, dns_answers=((GH, "github.com"),)))
        renamed = [m for m in self.agg.flush(2) if m["type"] == "node" and m["ip"] == GH]
        self.assertEqual(renamed[0]["name"], "github.com")

    def test_lan_broadcast_keeps_direction(self):
        self.agg.add(pkt("192.168.2.50", "224.0.0.251", l4="udp", sport=5353, dport=5353))
        [flow] = self.flows()
        self.assertEqual((flow["src"], flow["dst"], flow["bytes_up"]), ("192.168.2.50", "224.0.0.251", 100))


if __name__ == "__main__":
    unittest.main()
