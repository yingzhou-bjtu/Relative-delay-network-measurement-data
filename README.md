# Multipath Relative-Delay Measurement Dataset

This repository publishes the dataset used for studying relative-delay behavior
and latency correlation in heterogeneous multipath networks. The data includes DNS-derived IP lists and
Wireshark packet captures used during the measurement workflow.

## Project Identity

See [docs/PROJECT_IDENTITY.md](docs/PROJECT_IDENTITY.md) for the public name, repository slug, scope, and directory contract.

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
├── scripts/validate_data_manifest.py
├── README.md                    # dataset entry point
├── CITATION.cff                 # citation metadata
├── docs/DATA_MANIFEST.md        # committed data inventory
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
See [docs/DATA_MANIFEST.md](docs/DATA_MANIFEST.md) for the committed file
counts, naming pattern, and update policy.

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

Validate the committed dataset manifest:

```bash
python3 scripts/validate_data_manifest.py
```

For new packet captures, verify that each file opens with `tshark` or Wireshark
and record the capture date, tool version, and selection rule.

## Citation

Use `CITATION.cff` when citing this dataset.
