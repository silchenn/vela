# Detection rule design

Every rule follows the same template: **principle → decision logic → initial threshold → false-positive sources → how to verify**.
All thresholds are starting points, to be tuned by replaying real data from your own network.

| # | Rule | ATT&CK | Difficulty | Status |
|---|---|---|---|---|
| D1 | Port scan | T1046 Network Service Discovery | ⭐ | ⬜ |
| D2 | New device | T1200 Hardware Additions | ⭐ | ⬜ |
| D3 | Threat-intel hit | (mapped per intel category) | ⭐⭐ | ⬜ |
| D4 | C2 beaconing | T1071 Application Layer Protocol | ⭐⭐⭐ | ⬜ |
| D5 | DNS tunneling | T1071.004 DNS | ⭐⭐⭐ | ⬜ |
| D6 | Data exfiltration | T1048 / T1041 | ⭐⭐⭐ | ⬜ |

---

## D1 Port scan · T1046

- **Principle**: a scanner touches many ports on one host (vertical) or the same port on many hosts (horizontal) within a short time.
- **Decision**: within a sliding window, for one source IP:
  - vertical: number of distinct ports on one target ≥ threshold;
  - horizontal: number of distinct target hosts on one port ≥ threshold;
  - weighting: a high share of failed connections (RST, unanswered SYN) raises confidence.
- **Initial threshold**: ≥ 20 distinct ports or ≥ 15 distinct hosts within 60 seconds.
- **False positives**: P2P software, games, LAN discovery protocols (mDNS, SSDP); these need an allowlist.
- **Verify**: scan your own lab network once with `nmap -sS` and once with `nmap -sT`, and compare what gets detected.

## D2 New device · T1200

- **Principle**: a never-before-seen MAC address shows up on the LAN.
- **Decision**: keep a table of known devices (MAC, first seen, vendor OUI); alert the first time a new MAC appears, and the frontend "births a new star" that flashes.
- **False positives**: phones' **MAC address randomization** makes the same phone look like a new device. Downgrade using the DHCP hostname and the OUI's "locally administered" bit.
- **Verify**: connect a new device to the Wi-Fi.

## D3 Threat-intel correlation

- **Principle**: an external IP or domain matches a public blocklist.
- **Sources**: FireHOL Level 1, abuse.ch (Feodo Tracker, URLhaus). Pulled periodically and cached locally.
- **Decision**: the peer IP of a connection, or a domain in a DNS query, matches → that star turns red.
- **False positives**: blocklists contain stale entries, and shared CDN IPs can be collateral damage. Alerts must name the source list and its update time.
- **Verify**: resolve or ping the test entries the intel source provides (**never actually visit malicious sites**).

### Idea: direct-to-IP connections (candidate rule)

- **Principle**: legitimate software almost always looks up a domain before connecting; malware often hard-codes its C2 address as an IP, so there's no DNS query beforehand, and often no SNI in the TLS handshake either.
- **Decision**: the destination IP of an outbound connection has neither a passive-DNS name nor an SNI (the node's `name_source` is `asn` or `null`), and it's a destination not seen before.
- **False positives**: DNS cache hits, long-lived connections opened before the backend started, and encrypted DNS all produce "no DNS seen". This needs a **warm-up period** (no alerts for the first few minutes after startup) and should only judge connections opened after startup (where the SYN was seen).
- **Verify**: `curl https://<IP>` directly, compared with `curl https://<domain>`.

## D4 C2 beaconing · T1071

- **Principle**: malware often calls back to its command server at fixed intervals, so connection intervals are unusually regular, while human activity is random.
- **Decision**: for each (internal host, external destination) pair, collect the intervals between the last N connections:
  - a very low coefficient of variation (stddev / mean) → regular;
  - near-identical byte counts per connection → bonus;
  - sustained long enough (e.g. ≥ 1 hour, ≥ 20 connections).
- **Initial threshold**: coefficient of variation < 0.1 and ≥ 20 connections.
- **False positives**: OS update checks, NTP, cloud sync and IoT heartbeats are all very regular! This needs an allowlist plus threat-intel cross-checks, and it's the part of this rule most worth discussing in depth in the docs.
- **Verify**: a small script that hits your own VPS every 30 seconds (with ±5% jitter).
- **Reference**: the beacon scoring approach of RITA (Active Countermeasures).

## D5 DNS tunneling · T1071.004

- **Principle**: data is encoded into subdomains and smuggled out through DNS queries.
- **Signals**:
  - very long subdomains (e.g. > 50 characters);
  - high character entropy (Shannon entropy > 4);
  - a surge in unique subdomains under one parent domain;
  - a high share of unusual record types such as TXT and NULL.
- **False positives**: CDNs and anti-spam services also use long random subdomains; allowlist by parent domain.
- **Verify**: set up a tunnel with dnscat2 or iodine in a lab (**only on your own network**).

## D6 Data exfiltration · T1048 / T1041

- **Principle**: a device's upload traffic suddenly far exceeds its own historical baseline.
- **Decision**: build an hourly upload-bytes baseline per device (mean + stddev, or median + MAD) and alert when the current value > baseline + k × dispersion; weight destinations seen for the first time.
- **Initial threshold**: k = 4 and an absolute value > 100 MB/hour.
- **False positives**: cloud backups (NAS → VPS), video uploads. Handle with a "known backup destinations" allowlist.
- **Verify**: upload a 1 GB file from one device to a new destination.

---

## Alert message format

```json
{
  "type": "alert",
  "ts": 1792564110000,
  "rule": "D1",
  "title": "Port scan",
  "attack": ["T1046"],
  "severity": "high",
  "src": "45.155.205.233",
  "dst": "192.168.1.1",
  "evidence": { "distinct_ports": 37, "window_s": 60, "syn_only_ratio": 0.92 }
}
```

The `evidence` field must let a person understand *why* something was judged abnormal; that's where the project shows its thinking most clearly.
