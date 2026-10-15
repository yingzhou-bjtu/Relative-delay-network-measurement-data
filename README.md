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

The validator defaults to the committed dataset layout, and the same entrypoint
can validate staged or relocated data without editing code:

```bash
python3 scripts/validate_data_manifest.py \
  --root /path/to/dataset \
  --dns-dir "1. Required files in the DNS resolution process" \
  --raw-dir "2. Raw data" \
  --expected-segments 1097 \
  --min-file-bytes 1 \
  --json-out results/data_manifest_check.json
```

The default manifest check also rejects empty expected DNS spreadsheets or
packet captures, which prevents placeholder files from satisfying the inventory.
Segment capture filenames must also keep unique timestamps that increase with
their segment IDs, so renamed or reordered capture files are reported. The
expected DNS and representative capture lists accept file names only, not paths,
so those checks cannot be configured to read outside their dataset directories.
Direct `ManifestSpec` construction requires those lists to be sequences of
strings, avoiding character-by-character parsing when a single filename is
passed by mistake.
The DNS and raw capture directory options are resolved under `--root`; to
validate an external copy, point `--root` at that dataset root instead of using
absolute child directory paths.
When the root path already exists, it must be a directory rather than a file, so
misconfigured dataset roots fail before the manifest scan.
`--root`, `--dns-dir`, and `--raw-dir` expand `~` before this containment check,
so home-relative dataset paths work without bypassing the root boundary.
The optional `--json-out` report path must end in `.json` and is rejected when it
points inside the DNS input or raw packet-capture directories, which prevents a
validation report from overwriting committed measurement files. JSON reports are
written through a same-directory temporary file and atomically replaced, so an
interrupted run does not leave a partial report at the requested output path.

For new packet captures, verify that each file opens with `tshark` or Wireshark
and record the capture date, tool version, and selection rule.

## Citation

Use `CITATION.cff` when citing this dataset.
