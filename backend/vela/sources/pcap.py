"""Packet capture on a local interface (Scapy). Reads headers, DNS answers and the TLS ClientHello
server name only; payloads are never parsed or stored.

On macOS this needs read access to /dev/bpf*: membership in the access_bpf group (Wireshark's
ChmodBPF) is enough, otherwise run with sudo.
"""

# Type hint for "a function that takes X and returns Y"
from collections.abc import Callable

# Scapy protocol layers, the background sniffer, routing table, and IPv4 address lookup
from scapy.all import DNS, IP, TCP, UDP, AsyncSniffer, IPv6, Raw, conf, get_if_addr
# Lists every IPv6 address on this machine as (address, scope, interface) tuples
from scapy.arch import in6_getifaddr

# Our unified event type; every data source converts its raw data into this
from ..events import PacketEvent
# Pulls the server name out of TLS ClientHello messages, stitching split TCP segments together
from .tls import SniExtractor

# One shared extractor; parse() only ever runs on the sniffer thread, so no locking is needed
_sni = SniExtractor()


# Return all IP addresses (IPv4 + IPv6) that belong to the given interface, e.g. "en0"
def local_addresses(iface: str) -> set[str]:
    # Keep only the IPv6 addresses whose interface name matches iface
    ips = {addr for addr, _scope, name in in6_getifaddr() if name == iface}
    # Look up the interface's IPv4 address ("0.0.0.0" if it has none)
    v4 = get_if_addr(iface)
    # Add it only if it is a real address, not empty or the "none" placeholder
    if v4 and v4 != "0.0.0.0":
        ips.add(v4)
    # Hand back the set so the aggregator can tell "this machine" apart from others
    return ips


# Return the default gateway (router) IP, or None if there is no default route
def default_gateway() -> str | None:
    # Ask the routing table how to reach 0.0.0.0 (the default route); item [2] is the next-hop gateway
    gw = conf.route.route("0.0.0.0")[2]
    # "0.0.0.0" as a gateway means no gateway exists, so report None instead
    return None if gw == "0.0.0.0" else gw


# Turn one captured Scapy packet into a PacketEvent, or None if we don't care about it
def parse(pkt) -> PacketEvent | None:
    # Find the IP layer: try IPv4 first, fall back to IPv6
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    # Not an IP packet at all (e.g. ARP), so skip it
    if ip is None:
        return None
    # Find the transport layer (layer 4): TCP first, then UDP
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    # Neither TCP nor UDP (e.g. ICMP ping has no ports), so skip it
    if l4 is None:
        return None
    # Packet size: IPv4 "len" already includes the header; IPv6 "plen" excludes the fixed 40-byte header, so add it
    size = ip.len if isinstance(ip, IP) else ip.plen + 40
    # Build and return the unified event from the header fields
    return PacketEvent(
        # Capture timestamp in seconds since 1970 (converted from Scapy's high-precision decimal)
        ts=float(pkt.time),
        # Source IP address as a string
        src=ip.src,
        # Destination IP address as a string
        dst=ip.dst,
        # Transport protocol name; needed because port 443 over UDP is QUIC, over TCP is HTTPS
        l4="tcp" if isinstance(l4, TCP) else "udp",
        # Source port
        sport=l4.sport,
        # Destination port
        dport=l4.dport,
        # Packet size in bytes, computed above
        size=size,
        # TCP flags as text like "S" (SYN), "SA" (SYN-ACK), "R" (RST); UDP has none. Reserved for port-scan detection
        tcp_flags=str(l4.flags) if isinstance(l4, TCP) else "",
        # If this is a DNS response, the (ip, domain) pairs it contains; otherwise an empty tuple
        dns_answers=_dns_answers(pkt),
        # If this TCP segment completes a TLS ClientHello, the server name the client asked for
        sni=_tls_sni(pkt, ip, l4) if isinstance(l4, TCP) else "",
    )


# Return the SNI from a TLS ClientHello carried in this TCP segment, or "" if there isn't one
def _tls_sni(pkt, ip, tcp) -> str:
    # Raw holds the TCP payload bytes (Scapy doesn't decode TLS unless asked); no payload means nothing to read
    raw = pkt.getlayer(Raw)
    if raw is None:
        return ""
    # Hand the bytes to the extractor, keyed by the connection's 4-tuple so split segments get reassembled
    return _sni.feed((ip.src, tcp.sport, ip.dst, tcp.dport), raw.load)


# Extract (ip, queried domain) pairs from a DNS response packet
def _dns_answers(pkt) -> tuple[tuple[str, str], ...]:
    # Find the DNS layer, if there is one
    dns = pkt.getlayer(DNS)
    # Skip if: no DNS layer, it's a query not a response (qr=0), it has no answers, or no question section
    if dns is None or not dns.qr or not dns.ancount or not dns.qd:
        return ()
    # Take the domain the user asked for (bytes like b"github.com."), decode to text, drop the trailing dot
    qname = dns.qd[0].qname.decode(errors="replace").rstrip(".")
    # Build a tuple of (answer IP, queried domain) pairs
    return tuple(
        # Each pair maps the returned IP address to the domain the user queried
        (rr.rdata, qname)
        # Walk through every record in the answer section
        for rr in dns.an
        # Keep only address records: type 1 = A (IPv4), type 28 = AAAA (IPv6); skip CNAME etc.
        if rr.type in (1, 28)  # A / AAAA
    )


# A data source that captures packets from a local network interface
class PcapSource:
    # Remember which interface to capture on; capture doesn't start until start() is called
    def __init__(self, iface: str):
        # Interface name, e.g. "en0"
        self.iface = iface
        # The running sniffer; None means not capturing
        self._sniffer: AsyncSniffer | None = None

    # Start capturing; on_event is called once for every packet that parses into a PacketEvent
    def start(self, on_event: Callable[[PacketEvent], None]) -> None:
        # Callback Scapy runs (in its own background thread) for each captured packet
        def handle(pkt):
            # Convert the raw packet into our event format
            ev = parse(pkt)
            # Only forward packets we care about (IP + TCP/UDP)
            if ev is not None:
                on_event(ev)

        # Create a background sniffer: kernel-side filter keeps only IPv4/IPv6, call handle per packet, don't keep packets in memory
        self._sniffer = AsyncSniffer(iface=self.iface, filter="ip or ip6", prn=handle, store=False)
        # Launch the sniffer thread; this returns immediately
        self._sniffer.start()

    # Stop capturing and release the interface
    def stop(self) -> None:
        # Only act if a sniffer is actually running
        if self._sniffer is not None:
            # Tell the sniffer thread to stop and wait for it to finish
            self._sniffer.stop()
            # Forget it so stop() is safe to call twice and start() can be called again
            self._sniffer = None
