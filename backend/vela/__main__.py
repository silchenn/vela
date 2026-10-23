"""python -m vela：本机抓包 → 聚合 → WebSocket。"""

import argparse
import asyncio
import ipaddress
import os
import secrets
import sys

from .aggregator import Aggregator


def main() -> None:
    parser = argparse.ArgumentParser(prog="vela", description="Vela 采集与推送服务")
    parser.add_argument("--iface", default="en0", help="抓包网卡（默认 en0）")
    parser.add_argument("--host", help="WebSocket 监听地址，只允许局域网或回环地址（默认网卡自身的 IPv4）")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=os.environ.get("VELA_TOKEN"), help="连接口令，也可用环境变量 VELA_TOKEN；不填则随机生成")
    parser.add_argument("--window-ms", type=int, default=200, help="聚合窗口（毫秒）")
    args = parser.parse_args()

    # Scapy 导入较慢，放到参数解析之后，--help 能立即返回
    from .server import run
    from .sources.pcap import PcapSource, default_gateway, local_addresses

    local_ips = local_addresses(args.iface)
    if not local_ips:
        sys.exit(f"网卡 {args.iface} 没有 IP 地址，用 --iface 指定其他网卡")
    host = args.host or next((ip for ip in local_ips if ":" not in ip), "127.0.0.1")
    addr = ipaddress.ip_address(host)
    if addr.is_unspecified or not (addr.is_private or addr.is_loopback):
        sys.exit(f"拒绝监听 {host}：这个服务暴露全部连接记录，只能绑定局域网或回环地址")
    token = args.token or secrets.token_urlsafe(16)

    aggregator = Aggregator(local_ips, gateway=default_gateway(), window_ms=args.window_ms)
    print(f"抓包网卡 {args.iface}，本机地址 {', '.join(sorted(local_ips))}", file=sys.stderr)
    print(f"WebSocket: ws://{host}:{args.port}/?token={token}", file=sys.stderr)
    try:
        asyncio.run(run(aggregator, PcapSource(args.iface), host, args.port, token))
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("没有抓包权限：把用户加入 access_bpf 组（安装 Wireshark 的 ChmodBPF），或用 sudo 运行")


if __name__ == "__main__":
    main()
