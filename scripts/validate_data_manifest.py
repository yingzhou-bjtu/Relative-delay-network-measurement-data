#!/usr/bin/env python3
"""Validate the committed dataset inventory."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DNS_DIR = ROOT / "1. Required files in the DNS resolution process"
RAW_DIR = ROOT / "2. Raw data"
SEGMENT_RE = re.compile(r"out_(\d{5})_(\d{14})\.pcap")


def main() -> int:
    required_dns = {"ip.xlsx", "url.xlsx"}
    dns_files = {path.name for path in DNS_DIR.iterdir() if path.is_file()}
    missing_dns = sorted(required_dns - dns_files)
    unexpected_dns = sorted(dns_files - required_dns)

    pcap_files = sorted(path.name for path in RAW_DIR.glob("*.pcap") if path.is_file())
    representative = {"1.pcap", "2.pcap", "3.pcap"}
    segments = []
    invalid = []
    for name in pcap_files:
        if name in representative:
            continue
        match = SEGMENT_RE.fullmatch(name)
        if match is None:
            invalid.append(name)
        else:
            segments.append(int(match.group(1)))

    expected_segments = set(range(1097))
    actual_segments = set(segments)
    report = {
        "dns_file_count": len(dns_files),
        "pcap_file_count": len(pcap_files),
        "representative_pcaps": sorted(representative & set(pcap_files)),
        "segment_count": len(segments),
        "first_segment": min(segments) if segments else None,
        "last_segment": max(segments) if segments else None,
        "missing_dns": missing_dns,
        "unexpected_dns": unexpected_dns,
        "invalid_pcap_names": invalid,
        "missing_segments": sorted(expected_segments - actual_segments),
        "extra_segments": sorted(actual_segments - expected_segments),
    }
    print(json.dumps(report, indent=2))

    failed = (
        missing_dns
        or unexpected_dns
        or len(pcap_files) != 1100
        or len(representative & set(pcap_files)) != 3
        or invalid
        or actual_segments != expected_segments
    )
    if failed:
        return 1
    print("DATA_MANIFEST_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
