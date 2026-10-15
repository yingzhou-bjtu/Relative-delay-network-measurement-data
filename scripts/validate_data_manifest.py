#!/usr/bin/env python3
"""Validate a multipath-delay dataset inventory."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


SEGMENT_RE = re.compile(r"out_(\d{5})_(\d{14})\.pcap")
DEFAULT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DNS_DIR = "1. Required files in the DNS resolution process"
DEFAULT_RAW_DIR = "2. Raw data"
DEFAULT_REPRESENTATIVE_PCAPS = ("1.pcap", "2.pcap", "3.pcap")
DEFAULT_DNS_FILES = ("ip.xlsx", "url.xlsx")


@dataclass(frozen=True)
class ManifestSpec:
    root: Path
    dns_dir: Path
    raw_dir: Path
    expected_dns_files: tuple[str, ...]
    representative_pcaps: tuple[str, ...]
    expected_segments: int
    min_file_bytes: int

    @property
    def expected_pcap_count(self) -> int:
        return len(self.representative_pcaps) + self.expected_segments

    def __post_init__(self) -> None:
        validate_file_names("expected_dns_files", self.expected_dns_files)
        validate_file_names("representative_pcaps", self.representative_pcaps)
        validate_nonnegative_int("expected_segments", self.expected_segments)
        validate_nonnegative_int("min_file_bytes", self.min_file_bytes)


def validate_nonnegative_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def validate_file_names(field_name: str, names: Sequence[str]) -> None:
    if not names:
        raise ValueError(f"{field_name} must include at least one file name")
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise ValueError(
            f"{field_name} contains duplicate names: {', '.join(duplicates)}"
        )
    invalid = sorted(
        name
        for name in names
        if name in {"", ".", ".."}
        or "/" in name
        or "\\" in name
        or Path(name).is_absolute()
    )
    if invalid:
        raise ValueError(
            f"{field_name} entries must be file names, not paths: {', '.join(invalid)}"
        )


def parse_csv_names(raw: str) -> tuple[str, ...]:
    names = tuple(name.strip() for name in raw.split(",") if name.strip())
    if not names:
        raise argparse.ArgumentTypeError("at least one comma-separated name is required")
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise argparse.ArgumentTypeError(
            f"duplicate comma-separated names are not allowed: {', '.join(duplicates)}"
        )
    try:
        validate_file_names("comma-separated names", names)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return names


def resolve_dataset_dir(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    resolved = (path if path.is_absolute() else root / path).resolve()
    if not path_is_relative_to(resolved, root.resolve()):
        raise ValueError("dataset directories must stay under root")
    return resolved


def path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def resolve_report_path(path: Path, spec: ManifestSpec) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.suffix.lower() != ".json":
        raise ValueError(f"json_out must end with .json: {path}")
    if resolved.exists() and resolved.is_dir():
        raise ValueError(f"json_out is a directory, not a file: {path}")
    protected_dirs = (spec.dns_dir, spec.raw_dir)
    if any(path_is_relative_to(resolved, protected_dir) for protected_dir in protected_dirs):
        raise ValueError(
            "json_out must not be written inside the DNS input or raw packet-capture directories"
        )
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--dns-dir", default=DEFAULT_DNS_DIR)
    parser.add_argument("--raw-dir", default=DEFAULT_RAW_DIR)
    parser.add_argument(
        "--expected-dns-files",
        type=parse_csv_names,
        default=DEFAULT_DNS_FILES,
        help="Comma-separated DNS input filenames.",
    )
    parser.add_argument(
        "--representative-pcaps",
        type=parse_csv_names,
        default=DEFAULT_REPRESENTATIVE_PCAPS,
        help="Comma-separated non-segment capture filenames.",
    )
    parser.add_argument("--expected-segments", type=int, default=1097)
    parser.add_argument(
        "--min-file-bytes",
        type=int,
        default=1,
        help="Minimum accepted size for each expected dataset file.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path for the validation report JSON.",
    )
    return parser


def manifest_spec_from_args(args: argparse.Namespace) -> ManifestSpec:
    root = args.root.expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise ValueError(f"root is not a directory: {args.root}")
    return ManifestSpec(
        root=root,
        dns_dir=resolve_dataset_dir(root, str(args.dns_dir)).resolve(),
        raw_dir=resolve_dataset_dir(root, str(args.raw_dir)).resolve(),
        expected_dns_files=tuple(args.expected_dns_files),
        representative_pcaps=tuple(args.representative_pcaps),
        expected_segments=int(args.expected_segments),
        min_file_bytes=int(args.min_file_bytes),
    )


def list_file_names(directory: Path, pattern: str = "*") -> tuple[str, ...]:
    if not directory.is_dir():
        return ()
    return tuple(sorted(path.name for path in directory.glob(pattern) if path.is_file()))


def undersized_files(directory: Path, file_names: Sequence[str], min_file_bytes: int) -> list[str]:
    undersized = []
    for name in file_names:
        path = directory / name
        if path.is_file() and path.stat().st_size < min_file_bytes:
            undersized.append(name)
    return sorted(undersized)


def validate_manifest(spec: ManifestSpec) -> tuple[dict[str, object], bool]:
    required_dns = set(spec.expected_dns_files)
    dns_files = set(list_file_names(spec.dns_dir))
    missing_dns = sorted(required_dns - dns_files)
    unexpected_dns = sorted(dns_files - required_dns)

    pcap_files = list_file_names(spec.raw_dir, "*.pcap")
    representative = set(spec.representative_pcaps)
    segment_rows: list[tuple[int, str, str]] = []
    invalid: list[str] = []
    for name in pcap_files:
        if name in representative:
            continue
        match = SEGMENT_RE.fullmatch(name)
        if match is None:
            invalid.append(name)
        else:
            segment_rows.append((int(match.group(1)), match.group(2), name))

    segments = [segment_id for segment_id, _timestamp, _name in segment_rows]
    segment_timestamps = [timestamp for _segment_id, timestamp, _name in segment_rows]
    expected_segments = set(range(spec.expected_segments))
    actual_segments = set(segments)
    duplicate_segments = sorted(
        segment for segment, count in Counter(segments).items() if count > 1
    )
    duplicate_timestamps = sorted(
        timestamp for timestamp, count in Counter(segment_timestamps).items() if count > 1
    )
    non_monotonic_timestamps: list[str] = []
    previous_timestamp: str | None = None
    for _segment_id, timestamp, name in sorted(segment_rows):
        if previous_timestamp is not None and timestamp <= previous_timestamp:
            non_monotonic_timestamps.append(name)
        previous_timestamp = timestamp
    present_representative_pcaps = sorted(representative & set(pcap_files))
    missing_representative_pcaps = sorted(representative - set(pcap_files))
    report = {
        "root": str(spec.root),
        "dns_dir": str(spec.dns_dir),
        "raw_dir": str(spec.raw_dir),
        "dns_file_count": len(dns_files),
        "pcap_file_count": len(pcap_files),
        "representative_pcaps": present_representative_pcaps,
        "missing_representative_pcaps": missing_representative_pcaps,
        "segment_count": len(segments),
        "first_segment": min(segments) if segments else None,
        "last_segment": max(segments) if segments else None,
        "first_segment_timestamp": min(segment_timestamps) if segment_timestamps else None,
        "last_segment_timestamp": max(segment_timestamps) if segment_timestamps else None,
        "missing_dns": missing_dns,
        "unexpected_dns": unexpected_dns,
        "invalid_pcap_names": invalid,
        "duplicate_segment_ids": duplicate_segments,
        "duplicate_segment_timestamps": duplicate_timestamps,
        "non_monotonic_segment_timestamps": non_monotonic_timestamps,
        "missing_segments": sorted(expected_segments - actual_segments),
        "extra_segments": sorted(actual_segments - expected_segments),
        "min_file_bytes": spec.min_file_bytes,
        "undersized_dns_files": undersized_files(
            spec.dns_dir, spec.expected_dns_files, spec.min_file_bytes
        ),
        "undersized_pcap_files": undersized_files(
            spec.raw_dir, pcap_files, spec.min_file_bytes
        ),
    }

    failed = (
        missing_dns
        or unexpected_dns
        or len(pcap_files) != spec.expected_pcap_count
        or missing_representative_pcaps
        or invalid
        or duplicate_segments
        or duplicate_timestamps
        or non_monotonic_timestamps
        or actual_segments != expected_segments
        or report["undersized_dns_files"]
        or report["undersized_pcap_files"]
    )
    return report, bool(failed)


def write_report_json(path: Path, report_json: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(report_json)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        temp_path.replace(path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        spec = manifest_spec_from_args(args)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        json_out = (
            resolve_report_path(args.json_out, spec)
            if args.json_out is not None
            else None
        )
    except ValueError as exc:
        parser.error(str(exc))

    report, failed = validate_manifest(spec)
    report_json = json.dumps(report, indent=2)
    print(report_json)
    if json_out is not None:
        write_report_json(json_out, report_json)

    if failed:
        return 1
    print("DATA_MANIFEST_CHECK_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
