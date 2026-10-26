# Vela

> A visual intrusion detection system for your home network: network traffic rendered as a universe you can observe.

- **Stars**: your router, this machine, NAS, cloud servers, everyday internet services
- **Lanes**: connections between IPs; the speed and density of the light trails follow the transfer rate
- **Colors**: HTTPS cyan · HTTP white · DNS violet · QUIC amber · alerts red
- **Alerts**: port scans, new devices, beaconing, DNS tunneling, data exfiltration… each tagged with its MITRE ATT&CK technique ID

<!-- TODO: put an eye-catching 3-second demo GIF here: docs/assets/demo.gif -->

## Quick start (simulated data)

**Live demo**: <https://silchenn.github.io/vela/> (setup in [docs/DEPLOY.md](docs/DEPLOY.md))

The frontend currently comes in two visual styles; the final one hasn't been picked yet. Switch between them from the top-left corner of either page:

| Style | File | Online |
|---|---|---|
| Star Lanes | `frontend/index.html` | <https://silchenn.github.io/vela/> |
| Cyberpunk | `frontend/cyber.html` | <https://silchenn.github.io/vela/cyber.html> |

**Run locally**: no dependencies and no packet-capture setup needed.

```bash
git clone https://github.com/silchenn/vela.git
```

Then open `frontend/index.html` in a browser (double-click it, or run `open frontend/index.html` on macOS).

> The pages load Three.js from the jsDelivr CDN, so the first load needs an internet connection.

The Star Lanes page has five drills: big download, 4K video, DNS storm, port scan and NAS outage. The Cyberpunk page has a DDoS attack and a high-load torrent. On both, click a node to follow its inbound and outbound traffic.

## Live mode (real traffic)

Start the backend (see [backend/README.md](backend/README.md)) and open one of the frontend links it prints. The pages then show this machine's real connections instead of simulated ones.

## Repository layout

```
vela/
├── frontend/           3D visualization (Three.js single-file prototypes)
│   ├── index.html      Star Lanes style
│   ├── cyber.html      Cyberpunk style
│   └── live.js         shared live-data layer (WebSocket → scene)
├── backend/            capture, aggregation and push (Python, see backend/README.md)
└── docs/
    ├── ROADMAP.md      positioning, roadmap and development notes
    ├── DETECTIONS.md   detection rule design (with ATT&CK mapping)
    ├── ARCHITECTURE.md architecture, capture points and message formats
    └── DEPLOY.md       publishing to GitHub and the online demo
```

## Status

| Module | Status |
|---|---|
| Frontend prototype (simulated data) | ✅ Done |
| Backend capture: local packet capture → aggregation → WebSocket | ✅ Done |
| Frontend live mode | ✅ Done |
| Node naming: DNS / TLS SNI / ASN | ✅ Done |
| Backend capture: gateway conntrack | ⬜ Planned |
| Detection engine | ⬜ Planned |
| Suricata / Zeek integration | ⬜ Planned |

## Intended use

Use this project only to monitor networks and devices **you own or are explicitly authorized to monitor**. Run packet captures, port scans and other attack/defense demos only in your own lab environment.

## License

[MIT](LICENSE)
