# Data Manifest

This manifest describes the committed dataset files without duplicating the
large packet captures.

## Directory Summary

| Directory | File count | Purpose |
| --- | ---: | --- |
| `1. Required files in the DNS resolution process/` | 2 | DNS input and resolved IP metadata used before packet capture analysis. |
| `2. Raw data/` | 1100 | Raw packet captures in `pcap` format. |

## DNS Resolution Inputs

| File | Description |
| --- | --- |
| `1. Required files in the DNS resolution process/url.xlsx` | NTP server URL list used during DNS resolution. |
| `1. Required files in the DNS resolution process/ip.xlsx` | Resolved IP metadata. |

## Packet Captures

The raw capture directory contains:

- `1.pcap`, `2.pcap`, and `3.pcap`: representative packet captures.
- `out_00000_20221205162552.pcap` through
  `out_01096_20221205213656.pcap`: segmented Wireshark packet captures.

Use packet-analysis tools directly on individual captures, for example:

```bash
tshark -r "2. Raw data/1.pcap" -q -z io,stat,1
```

When adding new data, update this manifest with the file count, naming pattern,
capture source, capture date range, and any preprocessing applied.
