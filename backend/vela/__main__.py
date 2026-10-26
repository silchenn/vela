"""python -m vela: local packet capture → aggregation → WebSocket."""

import argparse
import asyncio
import errno
import ipaddress
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import quote

from .aggregator import Aggregator
from .asn import load_default


def main() -> None:
    parser = argparse.ArgumentParser(prog="vela", description="Vela capture and push service")
    parser.add_argument("--iface", default="en0", help="interface to capture on (default: en0)")
    parser.add_argument("--host", help="WebSocket listen address; LAN or loopback only (default: the interface's own IPv4)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=os.environ.get("VELA_TOKEN"), help="connection token, or set VELA_TOKEN; random if omitted")
    parser.add_argument("--window-ms", type=int, default=200, help="aggregation window in milliseconds")
    parser.add_argument("--no-asn", action="store_true", help="skip the ASN database (external nodes won't show their organization)")
    args = parser.parse_args()

    # Importing Scapy is slow; do it after argument parsing so --help returns instantly
    from .server import run
    from .sources.pcap import PcapSource, default_gateway, local_addresses

    local_ips = local_addresses(args.iface)
    if not local_ips:
        sys.exit(f"interface {args.iface} has no IP address; pick another one with --iface")
    host = args.host or next((ip for ip in local_ips if ":" not in ip), "127.0.0.1")
    addr = ipaddress.ip_address(host)
    if addr.is_unspecified or not (addr.is_private or addr.is_loopback):
        sys.exit(f"refusing to listen on {host}: this service exposes every connection record, so it may only bind to a LAN or loopback address")
    token = args.token or secrets.token_urlsafe(16)

    asn_db = None if args.no_asn else load_default(Path(__file__).resolve().parents[1] / "data")
    aggregator = Aggregator(
        local_ips,
        gateway=default_gateway(),
        window_ms=args.window_ms,
        asn_lookup=asn_db.lookup if asn_db else None,
    )
    print(f"capturing on {args.iface}, local addresses: {', '.join(sorted(local_ips))}", file=sys.stderr)

    def print_links() -> None:
        # Printed only once the server is listening, so a busy port never yields links that can't connect
        ws_host = f"[{host}]" if ":" in host else host
        t = quote(token, safe="")  # characters such as & # or spaces in a custom token must be escaped in a URL
        print(f"WebSocket: ws://{ws_host}:{args.port}/?token={t}", file=sys.stderr)
        frontend = Path(__file__).resolve().parents[2] / "frontend"
        for page, style in (("index.html", "Star Lanes"), ("cyber.html", "Cyberpunk")):
            if (frontend / page).exists():
                print(f"Frontend ({style}): {(frontend / page).as_uri()}?ws={ws_host}:{args.port}&token={t}", file=sys.stderr)

    try:
        asyncio.run(run(aggregator, PcapSource(args.iface), host, args.port, token, on_ready=print_links))
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("no permission to capture: add your user to the access_bpf group (install Wireshark with ChmodBPF), or run with sudo")
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            sys.exit(f"port {args.port} is already in use: vela may already be running, or pick another port with --port")
        raise


if __name__ == "__main__":
    main()
