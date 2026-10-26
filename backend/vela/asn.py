"""Offline IP → ASN (autonomous system) lookup.

The internet is made of tens of thousands of autonomous systems (AS), and each one announces over
BGP "these IP ranges are mine". So any public IP can be traced to its AS number and organization,
e.g. 140.82.112.3 → AS36459 GITHUB. This doesn't depend on DNS, so DNS caching, long-lived
connections and encrypted DNS don't affect it.
Limitation: cloud IPs belong to the cloud provider (a site hosted on AWS only resolves to AMAZON).

Data comes from iptoasn.com (public domain, rebuilt hourly from BGP tables); it's downloaded on the
first run and queried offline afterwards.
File format: one "start_ip<TAB>end_ip<TAB>ASN<TAB>country<TAB>description" per line, sorted by start IP.
"""

import gzip
import socket
import sys
import time
import urllib.request
from bisect import bisect_right
from pathlib import Path

URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
MAX_AGE_DAYS = 30


def _ip_int(ip: str) -> tuple[int, int]:
    """Return (address family, address as an int). inet_pton is much faster than ipaddress for 700k+ rows."""
    if ":" in ip:
        return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, ip), "big")
    return 4, int.from_bytes(socket.inet_pton(socket.AF_INET, ip), "big")


def short_org(desc: str) -> str:
    """'GTELECOM-AS-AP Gtelecom Pty Ltd' → 'GTELECOM-AS-AP'; a node label only has room for one word."""
    return desc.split(" ", 1)[0]


class AsnDb:
    def __init__(self, rows):
        """rows: iterable of (start_ip, end_ip, asn, desc), sorted by address (the file already is)."""
        self._starts = {4: [], 6: []}
        self._ends = {4: [], 6: []}
        self._asns = {4: [], 6: []}
        self._orgs: dict[int, str] = {}
        for start, end, asn, desc in rows:
            if asn == 0:  # "Not routed": ranges no AS announces
                continue
            fam, s = _ip_int(start)
            self._starts[fam].append(s)
            self._ends[fam].append(_ip_int(end)[1])
            self._asns[fam].append(asn)
            self._orgs.setdefault(asn, desc)

    @classmethod
    def from_file(cls, path: Path) -> "AsnDb":
        def rows():
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    start, end, asn, _country, desc = line.rstrip("\n").split("\t", 4)
                    yield start, end, int(asn), desc

        return cls(rows())

    def lookup(self, ip: str) -> tuple[int, str] | None:
        """Return (ASN, organization description); None for private or unannounced addresses."""
        try:
            fam, x = _ip_int(ip)
        except OSError:
            return None
        i = bisect_right(self._starts[fam], x) - 1
        if i < 0 or x > self._ends[fam][i]:
            return None
        asn = self._asns[fam][i]
        return asn, self._orgs[asn]


def load_default(data_dir: Path) -> AsnDb | None:
    """Load the data in data_dir, re-downloading if missing or older than 30 days; returns None on failure so the service still runs."""
    path = data_dir / "ip2asn-combined.tsv.gz"
    stale = not path.exists() or time.time() - path.stat().st_mtime > MAX_AGE_DAYS * 86400
    if stale:
        try:
            print(f"downloading ASN database {URL} …", file=sys.stderr)
            data_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".part")
            with urllib.request.urlopen(URL, timeout=60) as resp, open(tmp, "wb") as out:
                out.write(resp.read())
            tmp.replace(path)
        except OSError as e:
            print(f"ASN database download failed ({e}); external nodes won't show their organization", file=sys.stderr)
            if not path.exists():
                return None
    t0 = time.monotonic()
    db = AsnDb.from_file(path)
    print(f"ASN database loaded ({time.monotonic() - t0:.1f}s)", file=sys.stderr)
    return db
