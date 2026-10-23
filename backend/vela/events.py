"""适配器输出的统一事件。每个数据源（抓包、conntrack、Suricata……）都转换成这里的类型。"""

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PacketEvent:
    ts: float  # 秒（epoch）
    src: str
    dst: str
    l4: str  # "tcp" | "udp"
    sport: int
    dport: int
    size: int  # IP 层长度（字节），不含载荷内容
    tcp_flags: str = ""  # 例如 "S"、"SA"、"R"；留给 D1 端口扫描检测
    dns_answers: tuple[tuple[str, str], ...] = ()  # DNS 响应里的 (ip, 查询的域名)
