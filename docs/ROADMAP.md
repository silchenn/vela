# Positioning and roadmap

> Written 2026-10-21. These are the conclusions of the planning discussion and the reference during development; come back and update this when things change.

## 1. Positioning

**Not "traffic visualization", but "a visual intrusion detection system for the home network".**

This is a first project in network security. To an interviewer, a flashy frontend is only a bonus; what really shows security skill is the **detection logic**:
behind every red lane there must be a detection principle, a justified threshold and a false-positive story you can explain clearly.

## 2. Feasibility notes (pitfall checklist)

### Data capture
- **This machine's interface only sees this machine's traffic.** To see the whole home, capture at the gateway:
  | Option | Visibility | Difficulty |
  |---|---|---|
  | Capture on this machine's interface | This machine's traffic | ⭐ good for an MVP |
  | OpenWrt soft router / Linux gateway | All devices' internet traffic | ⭐⭐ **recommended** |
  | Switch port mirroring | Including LAN-internal traffic | ⭐⭐⭐ |
- With a Linux gateway, prefer reading the **conntrack** table: it already has 5-tuples and byte counters at almost zero cost.
- **Scapy is slow** and only suitable for a prototype; production should use Go (gopacket) or eBPF.
- **Don't push individual packets to the frontend**: aggregate into flows on the backend and push every 100–250 ms.
- Inferring the protocol from the port is only an approximation (443 may also be QUIC/UDP); good enough for colors, not for precise analysis.
- Names like IP → "GitHub": capture DNS answers to maintain a domain→IP map, plus an offline ASN database (e.g. iptoasn / GeoLite2 ASN) to merge one company's IPs. Reverse DNS is mostly useless.
- Outage detection: periodic ping / ARP probes.
- Packet capture needs root (or BPF access on macOS); Windows needs Npcap.

### Transport
- The WebSocket only listens on LAN addresses and requires a token. **This service exposes every connection in the house; never expose it to the internet.**

### Rendering
- Hand particles to the GPU (shaders + Bézier curves); keep a fallback for bloom on 4K displays.
- **Node explosion** is the biggest visual problem: merge nodes by ASN, fade out and recycle idle nodes, and only draw the top N by traffic as stars.
- Use a layered concentric layout (this machine/gateway at the center → LAN inner ring → internet outer shell) rather than a pure force-directed one.
- **Tuning visuals usually takes longer than writing features.**

## 3. Security capabilities: detections

Ordered by difficulty; detailed design in [DETECTIONS.md](DETECTIONS.md):

1. Port scan detection (T1046)
2. New device alerts (T1200)
3. Threat-intel correlation (FireHOL, abuse.ch blocklists)
4. C2 beacon detection (T1071) — the most valuable
5. DNS tunneling detection (T1071.004)
6. Data exfiltration detection (T1048 / T1041)

**Every alert is tagged with its MITRE ATT&CK technique ID.**

## 4. "Industry-grade" data sources

Besides our own packet capture, the backend should ingest **Suricata (eve.json)** and **Zeek (conn.log / dns.log)**.
These are tools actually used in companies; having them in the project shows you understand the industry ecosystem.
Design it as adapters: different sources → one unified event format → detection engine → frontend.

## 5. Roadmap

| Stage | Scope | Estimate |
|---|---|---|
| **M0 Prototype** ✅ | Frontend + simulated data, five drill scenarios | Done |
| **M1 Real data** ✅ | Local capture / conntrack → aggregation → WebSocket; frontend switches to real data | Done (local capture) |
| **M2 First detections** | Port scan + new device + alert panel (with ATT&CK IDs) | 1–2 weeks |
| **M3 Node management** | DNS mapping, ASN merging, node lifecycle (naming via DNS / SNI / ASN already done) | 2–3 weeks |
| **M4 Advanced detections** | Beaconing, DNS tunneling, exfiltration baselines, threat intel | 1 month |
| **M5 Ecosystem** | Suricata / Zeek adapters | 1–2 weeks |
| **M6 Release polish** | GIF, attack/defense demo video, docs, sound, big-screen tuning | Ongoing |

Principle: **keep frontend and backend decoupled, and always keep the frontend's simulated-data mode**.

## 6. GitHub release checklist

- [ ] A GIF at the top of the README that grabs attention within three seconds
- [ ] One-click simulated mode so others don't need a capture setup
- [ ] DETECTIONS.md: each rule's logic, how thresholds were set, how false positives are handled
- [ ] Attack/defense demo: scan your own lab network with nmap and record the red lanes lighting up
- [ ] README states the intended use: only capture and scan your own networks and devices
- [x] Open-source license: MIT
- [x] GitHub Pages online demo (steps in [DEPLOY.md](DEPLOY.md))
