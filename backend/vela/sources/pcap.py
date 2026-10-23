"""本机网卡抓包（Scapy）。只读包头和 DNS 响应，不解析、不保存载荷。

macOS 上需要读 /dev/bpf*：用户在 access_bpf 组（Wireshark 的 ChmodBPF）即可，否则要 sudo。
"""

from collections.abc import Callable

from scapy.all import DNS, IP, TCP, UDP, AsyncSniffer, IPv6, conf, get_if_addr
from scapy.arch import in6_getifaddr

from ..events import PacketEvent


def local_addresses(iface: str) -> set[str]:
    ips = {addr for addr, _scope, name in in6_getifaddr() if name == iface}
    v4 = get_if_addr(iface)
    if v4 and v4 != "0.0.0.0":
        ips.add(v4)
    return ips


def default_gateway() -> str | None:
    gw = conf.route.route("0.0.0.0")[2]
    return None if gw == "0.0.0.0" else gw


def parse(pkt) -> PacketEvent | None:
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if l4 is None:
        return None
    size = ip.len if isinstance(ip, IP) else ip.plen + 40
    return PacketEvent(
        ts=float(pkt.time),
        src=ip.src,
        dst=ip.dst,
        l4="tcp" if isinstance(l4, TCP) else "udp",
        sport=l4.sport,
        dport=l4.dport,
        size=size,
        tcp_flags=str(l4.flags) if isinstance(l4, TCP) else "",
        dns_answers=_dns_answers(pkt),
    )


def _dns_answers(pkt) -> tuple[tuple[str, str], ...]:
    dns = pkt.getlayer(DNS)
    if dns is None or not dns.qr or not dns.ancount or not dns.qd:
        return ()
    # 记用户查询的域名，而不是 CNAME 链末端的 CDN 域名
    qname = dns.qd[0].qname.decode(errors="replace").rstrip(".")
    return tuple(
        (rr.rdata, qname)
        for rr in dns.an
        if rr.type in (1, 28)  # A / AAAA
    )


class PcapSource:
    def __init__(self, iface: str):
        self.iface = iface
        self._sniffer: AsyncSniffer | None = None

    def start(self, on_event: Callable[[PacketEvent], None]) -> None:
        def handle(pkt):
            ev = parse(pkt)
            if ev is not None:
                on_event(ev)

        self._sniffer = AsyncSniffer(iface=self.iface, filter="ip or ip6", prn=handle, store=False)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
