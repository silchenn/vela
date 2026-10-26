# backend

Capture, aggregation and push (roadmap M1). The current data source is **packet capture on this machine's interface**, so it only sees traffic in and out of this machine.

```
en0 capture (Scapy) → PacketEvent → aggregator (200 ms windows) → flow / node messages → WebSocket
```

## Install

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Run

```bash
.venv/bin/python -m vela                # captures en0, listens on en0's own IPv4:8765
.venv/bin/python -m vela --help         # interface, address, port, token, window length, --no-asn
```

On startup it prints the connection address, e.g. `ws://192.168.2.17:8765/?token=...`. Without a token, a random one is generated on every start; pin it with `--token` or the `VELA_TOKEN` environment variable.

The first run downloads an offline ASN database (~9 MB, from iptoasn.com) into `backend/data/`, refreshed every 30 days. It's used to label external IPs with their owning organization; pass `--no-asn` to skip it.

### Viewing it in the frontend

It also prints two frontend links (Star Lanes / Cyberpunk). Open either in a browser to enter live mode:

```
Frontend (Star Lanes): file:///.../frontend/index.html?ws=192.168.2.17:8765&token=...
```

Alternatively, open a frontend page first and paste the `ws://` address into its "Data source" box. The page reconnects automatically if the connection drops; click "Back to simulation" to return to simulated data.

Note: the online demo on GitHub Pages is an HTTPS page, and browsers won't let it connect to a LAN `ws://` address. Live mode only works with pages opened locally.

The links are printed only after the server is actually listening. They stop working if the backend restarts with a new random token, or if this machine's IP changes (e.g. after switching Wi-Fi). Use the links from the current run.

### Debug client

Watch the pushed messages with the debug client:

```bash
.venv/bin/python -m vela.watch 'ws://192.168.2.17:8765/?token=...'
```

### Permissions

On macOS, capturing means reading `/dev/bpf*`. Install Wireshark with ChmodBPF to add your user to the `access_bpf` group and run without sudo; otherwise run with `sudo`.

### Security

- Only LAN or loopback addresses can be bound; `0.0.0.0` and public addresses are refused.
- Connections with a wrong token get HTTP 401.
- Only packet headers, DNS answers and the TLS ClientHello server name are read; payloads are never parsed or stored.

## Code layout

| File | Purpose |
|---|---|
| `vela/events.py` | The unified `PacketEvent` every data-source adapter emits |
| `vela/sources/pcap.py` | Local packet-capture adapter |
| `vela/sources/tls.py` | Extracts the SNI from TLS ClientHello messages, reassembling split TCP segments |
| `vela/asn.py` | Offline IP → ASN / organization lookup |
| `vela/aggregator.py` | Aggregates into flows keyed by (this machine, peer, transport, service port); keeps the node table and names external nodes (DNS > SNI > ASN) |
| `vela/server.py` | WebSocket push: a new client first gets a node snapshot, then new nodes and flows every window |
| `vela/watch.py` | Debug client |

## Tests

```bash
.venv/bin/python -m unittest discover -s tests
```
