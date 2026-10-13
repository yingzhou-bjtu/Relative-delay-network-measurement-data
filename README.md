# Relative Delay Network Measurement Data

This repository publishes the dataset used for studying latency correlation in
heterogeneous multipath networks. The data includes DNS-derived IP lists and
Wireshark packet captures used during the measurement workflow.

## Repository Scope

This is a data repository, not an executable software package. The public value
is the provenance, directory meaning, and citation metadata for the measurement
files.

## Repository Layout

```text
.
├── 1. Required files in the DNS resolution process/
│   ├── url.xlsx                 # NTP server URLs used for DNS resolution
│   └── ip.xlsx                  # resolved IP metadata
├── 2. Raw data/
│   ├── 1.pcap, 2.pcap, 3.pcap  # representative packet captures
│   └── out_*.pcap              # raw Wireshark capture segments
├── README.md                    # dataset entry point
├── CITATION.cff                 # citation metadata
├── LICENSE                      # reuse terms
└── docs/OPEN_SOURCE_STANDARD.md # repository hygiene and dataset policy
```

## File Descriptions

### DNS resolution files

`url.xlsx` contains the NTP server URL list used during DNS resolution.
`ip.xlsx` contains resolved IP records and related metadata.

### Raw packet captures

The `2. Raw data/` directory contains packet captures in `pcap` format. These
files can be inspected with Wireshark, tshark, or other packet-analysis tools.

Example inspection command:

```bash
tshark -r "2. Raw data/1.pcap" -q -z io,stat,1
```

## Data Use Notes

- Treat packet captures as raw measurement artifacts.
- Do not add private captures, credentials, private IP inventories, or host
  identifiers without review.
- If new derived tables are added, place them in a clearly named `derived/` or
  `results/` directory and document how they were produced.
- For large new data files, prefer GitHub Releases, Git LFS, or an external
  dataset host and keep only metadata plus download instructions in Git.

## Validation

For metadata and documentation changes:

```bash
git diff --check
```

For new packet captures, verify that each file opens with `tshark` or Wireshark
and record the capture date, tool version, and selection rule.

## Citation

Use `CITATION.cff` when citing this dataset.
