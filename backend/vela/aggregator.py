"""把逐包事件按窗口聚合成 flow 消息，并维护节点表（node 消息）。

消息格式见 docs/ARCHITECTURE.md。
"""

import ipaddress
from collections import defaultdict

from .events import PacketEvent

# 按端口判断协议只是近似（见 ROADMAP），用于配色足够
KNOWN_PORTS = {53, 80, 443, 8080}
MAX_DNS_NAMES = 10_000


def classify(l4: str, port: int) -> str:
    if port == 53:
        return "dns"
    if port == 443:
        return "quic" if l4 == "udp" else "https"
    if port in (80, 8080):
        return "http"
    return "other"


def service_port(local_port: int, remote_port: int) -> int:
    """猜测哪一端是服务端口：优先已知端口，其次 <1024 的一端，否则取对端端口。"""
    for port, other in ((remote_port, local_port), (local_port, remote_port)):
        if port in KNOWN_PORTS or (port < 1024 <= other):
            return port
    return remote_port


class Aggregator:
    def __init__(self, local_ips: set[str], gateway: str | None = None, window_ms: int = 200):
        self.local_ips = local_ips
        self.gateway = gateway
        self.window_ms = window_ms
        # (src, dst, l4, port) -> [bytes_up, bytes_down]
        self._flows: dict[tuple[str, str, str, int], list[int]] = defaultdict(lambda: [0, 0])
        self._nodes: dict[str, dict] = {}
        self._dirty_nodes: dict[str, dict] = {}
        self._dns_names: dict[str, str] = {}

    def add(self, ev: PacketEvent) -> None:
        for ip, name in ev.dns_answers:
            self._learn_name(ip, name)

        # 统一以本机一侧为 src；两端都不是本机（局域网广播/组播）时保持原方向
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
        """取出本窗口的消息：先发新增/变更的节点，再发 flow。"""
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
        """当前节点快照，新客户端连上时先发一遍。"""
        return list(self._nodes.values())

    def _learn_name(self, ip: str, name: str) -> None:
        self._dns_names.pop(ip, None)
        self._dns_names[ip] = name
        if len(self._dns_names) > MAX_DNS_NAMES:
            del self._dns_names[next(iter(self._dns_names))]
        node = self._nodes.get(ip)
        if node and node["kind"] == "external" and node["name"] != name:
            node["name"] = name
            self._dirty_nodes[ip] = node

    def _touch_node(self, ip: str) -> None:
        if ip in self._nodes:
            return
        kind = self._kind(ip)
        name = {"local": "本机", "gateway": "网关"}.get(kind) or self._dns_names.get(ip)
        node = {"type": "node", "ip": ip, "name": name, "asn": None, "kind": kind, "online": True}
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
