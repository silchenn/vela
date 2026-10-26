"""The unified event adapters emit. Every data source (capture, conntrack, Suricata, …) converts into these types."""

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PacketEvent:
    ts: float  # seconds since the epoch
    src: str
    dst: str
    l4: str  # "tcp" | "udp"
    sport: int
    dport: int
    size: int  # IP-layer length in bytes; payload content is never kept
    tcp_flags: str = ""  # e.g. "S", "SA", "R"; reserved for D1 port-scan detection
    dns_answers: tuple[tuple[str, str], ...] = ()  # (ip, queried domain) pairs from a DNS answer
    sni: str = ""  # server name from a TLS ClientHello (belongs to dst)
