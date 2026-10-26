"""Aggregates per-packet events into per-window flow messages and maintains the node table (node messages).

Message formats are documented in docs/ARCHITECTURE.md.
"""

import ipaddress
from collections import defaultdict
from collections.abc import Callable

from .asn import short_org
from .events import PacketEvent

# Inferring the protocol from the port is only approximate (see ROADMAP), but good enough for colors
KNOWN_PORTS = {53, 80, 443, 8080}
MAX_NAMES = 10_000
# How reliable each naming source is: DNS (the domain actually queried) > SNI (domain in the TLS handshake) > ASN (owning organization)
NAME_PRIORITY = {"asn": 1, "sni": 2, "dns": 3}


def classify(l4: str, port: int) -> str:
    if port == 53:
        return "dns"
    if port == 443:
        return "quic" if l4 == "udp" else "https"
    if port in (80, 8080):
        return "http"
    return "other"


def service_port(local_port: int, remote_port: int) -> int:
    """Guess which side is the service port: a well-known port first, then the side below 1024, else the peer's port."""
    for port, other in ((remote_port, local_port), (local_port, remote_port)):
        if port in KNOWN_PORTS or (port < 1024 <= other):
            return port
    return remote_port


class Aggregator:
    def __init__(
        self,
        local_ips: set[str],
        gateway: str | None = None,
        window_ms: int = 200,
        asn_lookup: Callable[[str], tuple[int, str] | None] | None = None,
    ):
        self.local_ips = local_ips
        self.gateway = gateway
        self.window_ms = window_ms
        self.asn_lookup = asn_lookup
        # (src, dst, l4, port) -> [bytes_up, bytes_down]
        self._flows: dict[tuple[str, str, str, int], list[int]] = defaultdict(lambda: [0, 0])
        self._nodes: dict[str, dict] = {}
        self._dirty_nodes: dict[str, dict] = {}
        self._names: dict[str, tuple[str, str]] = {}  # ip -> (name, source); only names learned from DNS / SNI
        # Traffic may not cross the gateway right away; add it up front so the frontend shows its address as soon as it connects
        if gateway:
            self._touch_node(gateway)

    def add(self, ev: PacketEvent) -> None:
        for ip, name in ev.dns_answers:
            self._learn_name(ip, name, "dns")
        if ev.sni:
            self._learn_name(ev.dst, ev.sni, "sni")

        # Always make this machine's side the src; keep the original direction when neither end is local (LAN broadcast/multicast)
        if ev.dst in self.local_ips and ev.src not in self.local_ips:
            local, remote, lport, rport, upstream = ev.dst, ev.src, ev.dport, ev.sport, False
        else:
            local, remote, lport, rport, upstream = ev.src, ev.dst, ev.sport, ev.dport, True

        port = service_port(lport, rport)
        counters = self._flows[(local, remote, ev.l4, port)]
        counters[0 if upstream else 1] += ev.size
        self._touch_node(local)
        self._touch_node(remote)

    def flush(self, ts_ms: int) -> list[dict]:
        """Drain this window's messages: new/changed nodes first, then flows."""
        msgs = list(self._dirty_nodes.values())
        self._dirty_nodes.clear()
        for (src, dst, l4, port), (up, down) in self._flows.items():
            msgs.append({
                "type": "flow",
                "ts": ts_ms,
                "src": src,
                "dst": dst,
                "proto": classify(l4, port),
                "l4": l4,
                "port": port,
                "bytes_up": up,
                "bytes_down": down,
                "window_ms": self.window_ms,
            })
        self._flows.clear()
        return msgs

    def nodes(self) -> list[dict]:
        """Snapshot of current nodes, sent first to each new client."""
        return list(self._nodes.values())

    def _learn_name(self, ip: str, name: str, source: str) -> None:
        # Only a more reliable source may replace a name; a newer name from the same source wins (CDN IPs switch domains)
        old = self._names.get(ip)
        if old and NAME_PRIORITY[old[1]] > NAME_PRIORITY[source]:
            return
        self._names.pop(ip, None)
        self._names[ip] = (name, source)
        if len(self._names) > MAX_NAMES:
            del self._names[next(iter(self._names))]
        node = self._nodes.get(ip)
        if node and node["kind"] == "external" and (node["name"], node["name_source"]) != (name, source):
            if NAME_PRIORITY.get(node["name_source"], 0) <= NAME_PRIORITY[source]:
                node["name"], node["name_source"] = name, source
                self._dirty_nodes[ip] = node

    def _touch_node(self, ip: str) -> None:
        if ip in self._nodes:
            return
        kind = self._kind(ip)
        name, source = self._names.get(ip, (None, None))
        asn = org = None
        if kind == "external" and self.asn_lookup:
            found = self.asn_lookup(ip)
            if found:
                asn, org = f"AS{found[0]}", found[1]
                if name is None:
                    name, source = short_org(org), "asn"
        if kind in ("local", "gateway"):
            name, source = {"local": "This machine", "gateway": "Gateway"}[kind], None
        node = {
            "type": "node", "ip": ip, "name": name, "name_source": source,
            "asn": asn, "org": org, "kind": kind, "online": True,
        }
        self._nodes[ip] = node
        self._dirty_nodes[ip] = node

    def _kind(self, ip: str) -> str:
        if ip in self.local_ips:
            return "local"
        if ip == self.gateway:
            return "gateway"
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or addr.is_unspecified or ip == "255.255.255.255":
            return "multicast"
        if addr.is_private or addr.is_link_local:
            return "lan"
        return "external"
