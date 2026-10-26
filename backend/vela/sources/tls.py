"""Extract the SNI (Server Name Indication) from a TLS ClientHello.

HTTPS content is encrypted, but in the first handshake message, the ClientHello, the client has to
tell the server in plaintext which domain it wants, so the server can present the right
certificate. That field is the SNI. Even when DNS is cached and no DNS query hits the wire, every new
HTTPS connection still reveals its domain.

No SNI is visible for: connections using ECH (Encrypted Client Hello), QUIC (the SNI sits in the
encrypted Initial packet), and long-lived connections opened before the backend started.

A ClientHello can span several TCP segments (Chrome's is ~1.7 KB with post-quantum key exchange,
more than one segment), so SniExtractor stitches a connection's first segments together before parsing.
"""

MAX_HELLO = 16 * 1024  # give up beyond the maximum size of one TLS record
MAX_PENDING = 1024     # max connections waiting for more segments at once


def looks_like_client_hello(data: bytes) -> bool:
    # record type 0x16 = Handshake, major version 0x03, handshake type 0x01 = ClientHello
    return len(data) >= 6 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01


def parse_client_hello(data: bytes) -> str | None:
    """Return the SNI; "" for a complete hello without one; None if the data is still incomplete."""
    if len(data) < 9:
        return None
    if not looks_like_client_hello(data):
        return ""
    end = 9 + int.from_bytes(data[6:9], "big")  # 5-byte record header + 4-byte handshake header + handshake body
    if len(data) < end:
        return None
    try:
        pos = 9 + 2 + 32                                   # skip client_version and random
        pos += 1 + data[pos]                               # session_id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # cipher_suites
        pos += 1 + data[pos]                               # compression_methods
        ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(ext_end, end):
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0:  # server_name extension
                # server_name_list length(2) + name_type(1, 0 = host_name) + name length(2) + name
                if data[pos + 2] != 0:
                    return ""
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                return data[pos + 5:pos + 5 + name_len].decode("ascii", errors="replace").lower()
            pos += ext_len
    except IndexError:
        pass
    return ""


class SniExtractor:
    """Stitch a ClientHello's TCP segments per connection (4-tuple) and parse out the SNI."""

    def __init__(self) -> None:
        self._pending: dict[tuple, bytes] = {}

    def feed(self, key: tuple, payload: bytes) -> str:
        """Feed one TCP segment's payload; returns the domain once the SNI is complete, else ""."""
        if key not in self._pending and not looks_like_client_hello(payload):
            return ""
        buf = self._pending.pop(key, b"") + payload
        sni = parse_client_hello(buf)
        if sni is None:
            if len(buf) < MAX_HELLO:
                self._pending[key] = buf
                if len(self._pending) > MAX_PENDING:
                    del self._pending[next(iter(self._pending))]
            return ""
        return sni
