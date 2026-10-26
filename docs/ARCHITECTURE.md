# Architecture

```
┌──────────────────────── Data sources ────────────────────────┐
│ Local capture │ Gateway conntrack │ Suricata eve.json │ Zeek logs │
└───────┬───────────────┬──────────────────┬───────────────────┘
        └──── Adapters (normalize into flow events) ────┐
                                                        ▼
                         Aggregator (one window every 200 ms)
                         + node management (DNS mapping / ASN merging / lifecycle)
                                                        │
                                  ┌─────────────────────┴──────────────┐
                                  ▼                                    ▼
                       Detection engine (D1–D6)            Device liveness (ping / ARP)
                                  └─────────────────┬──────────────────┘
                                                    ▼
                               WebSocket (LAN only + token)
                                                    ▼
                    Frontend: Three.js star map (simulated mode always kept)
```

## Technology choices (tentative)

| Layer | Prototype | Production |
|---|---|---|
| Capture | Python + Scapy | Go (gopacket) / conntrack / eBPF |
| Aggregation & detection | Python | Go |
| Transport | WebSocket | WebSocket |
| Frontend | Three.js single file | Three.js + Vite modules |

## Where data is captured

> The current backend captures on this machine's network interface. The frontend runs on its built-in simulator unless opened in live mode (see [backend/README.md](../backend/README.md)).

### Capture point evolution

| Stage | Capture point | What it sees | What it can't see |
|---|---|---|---|
| **M1 start** | This machine's interface (`en0` is usually Wi-Fi on a Mac) | Every connection in and out of this machine | Other devices' traffic (on switched networks and encrypted Wi-Fi, your interface never receives other hosts' packets) |
| **Recommended target** | The gateway (OpenWrt soft router / Linux gateway), reading conntrack or capturing packets | Every device's traffic to and from the internet | Traffic between LAN devices |
| **Advanced** | Managed switch port mirroring | Including LAN-internal traffic | — |

In local-capture mode, only "this machine" has lanes to the internet. That's a consequence of where we capture, not a bug.

### Metadata only, never content

Captured fields: source/destination IP, ports, protocol, packet size, timestamp, plus domain names from DNS answers and TLS SNI.
**Payloads are never parsed or stored** (beyond the TLS handshake header that carries the SNI). Most traffic is HTTPS / QUIC and encrypted anyway;
rules D1–D6 depend on metadata alone, which is the mainstream approach of commercial NDR (Network Detection and Response) products.

### Notes on capturing locally on macOS

- **Permissions**: capturing means reading `/dev/bpf*`, which requires `sudo` by default. The ChmodBPF helper that ships with Wireshark grants access to regular users (via the `access_bpf` group).
- **VPNs / proxies**: with Clash, Surge or similar running, most of what `en0` sees is an encrypted tunnel to the proxy server, drawn as one thick lane. To see the real destinations:
  - capture on the virtual interface the proxy creates (`utun*`); or
  - read the proxy's own connection log / API.
- **A lightweight option without packet capture**: read the connection table with `nettop` or `lsof -i`. It's cheap, needs no packet parsing, and also gives the **name of the process that opened each connection**. A gateway can never see that, so it could become a signature feature of local mode (e.g. "which program is quietly phoning home").

## Message formats

### flow: one connection within one aggregation window

```json
{
  "type": "flow",
  "ts": 1792564110000,
  "src": "192.168.1.10",
  "dst": "140.82.112.3",
  "proto": "https",
  "l4": "tcp",
  "port": 443,
  "bytes_up": 4096,
  "bytes_down": 182344,
  "window_ms": 200
}
```

`proto` is one of `https` / `quic` / `http` / `dns` / `other` / `alert`. It's guessed from the port, so it's approximate; traffic on ports other than 53/80/443/8080 is `other`.

`l4` is the transport layer (`tcp` / `udp`), and `port` is the inferred service port. In local-capture mode `src` is always this machine's side and `bytes_up` is what this machine sent; broadcast/multicast packets where neither end is this machine keep their original direction.

### node: node info and state

```json
{
  "type": "node",
  "ip": "140.82.112.3",
  "name": "github.com",
  "name_source": "sni",
  "asn": "AS36459",
  "org": "GITHUB",
  "kind": "external",
  "online": true
}
```

`kind` is one of `local` (this machine) / `gateway` (default gateway) / `lan` (private address) / `multicast` (multicast and broadcast) / `external`. `asn` and `org` are only filled in for external nodes, and are `null` when the lookup finds nothing. A new client first receives every known node, then only new or renamed ones.

### Where node names come from

Packets carry IP addresses, not domain names. An external node's `name` is taken from three sources in order of reliability, and `name_source` says which one was used:

| `name_source` | Source | When it's unavailable |
|---|---|---|
| `dns` | Captured DNS answers: queried domain → returned IP (passive DNS) | OS/browser DNS cache hits; long-lived connections opened before the backend started; encrypted DNS (DoH / DoT) |
| `sni` | The plaintext server name in the TLS ClientHello, reassembled when it spans several TCP segments | Connections opened before startup; ECH (Encrypted ClientHello); QUIC (the SNI sits in the encrypted Initial packet, not parsed yet) |
| `asn` | Offline ASN database: the BGP autonomous system and organization owning the IP (iptoasn.com data, stored in `backend/data/`, refreshed every 30 days) | Private addresses; cloud IPs only resolve to the cloud provider (a site hosted on AWS shows as AMAZON) |
| `null` | None of the above; only the IP is shown | — |

Priority is `dns > sni > asn`: a more reliable source can replace a less reliable one, never the other way round. One IP can serve many domains (CDNs), so a name means "the name this device used to reach this IP", not the IP's one true name. Reverse DNS (PTR) is mostly empty or an internal hosting name, so it isn't used.

### alert: see [DETECTIONS.md](DETECTIONS.md#alert-message-format)

## Security notes

- The WebSocket server only binds to LAN or loopback addresses and checks a token on connect.
- Payloads are never persisted; only metadata is kept.
- The capture process runs with least privilege (on Linux, `CAP_NET_RAW` instead of root).
