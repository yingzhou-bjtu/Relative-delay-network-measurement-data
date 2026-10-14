#!/usr/bin/env python3
"""Lightweight checks for the dataset manifest validator."""

from __future__ import annotations

import tempfile
from pathlib import Path

from validate_data_manifest import (
    DEFAULT_DNS_DIR,
    DEFAULT_RAW_DIR,
    ManifestSpec,
    validate_manifest,
)


def touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")


def make_dataset(root: Path) -> ManifestSpec:
    for name in ("ip.xlsx", "url.xlsx"):
        touch(root / DEFAULT_DNS_DIR / name)
    for name in ("1.pcap", "2.pcap", "3.pcap"):
        touch(root / DEFAULT_RAW_DIR / name)
    touch(root / DEFAULT_RAW_DIR / "out_00000_20221205162552.pcap")
    touch(root / DEFAULT_RAW_DIR / "out_00001_20221205162605.pcap")
    return ManifestSpec(
        root=root,
        dns_dir=root / DEFAULT_DNS_DIR,
        raw_dir=root / DEFAULT_RAW_DIR,
        expected_dns_files=("ip.xlsx", "url.xlsx"),
        representative_pcaps=("1.pcap", "2.pcap", "3.pcap"),
        expected_segments=2,
        min_file_bytes=1,
    )


def test_validate_manifest_accepts_parameterized_dataset() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        report, failed = validate_manifest(spec)
        assert not failed
        assert report["pcap_file_count"] == 5
        assert report["segment_count"] == 2


def test_validate_manifest_reports_missing_segment() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        (spec.raw_dir / "out_00001_20221205162605.pcap").unlink()
        report, failed = validate_manifest(spec)
        assert failed
        assert report["missing_segments"] == [1]


def test_validate_manifest_rejects_empty_dataset_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        (spec.raw_dir / "1.pcap").write_bytes(b"")
        report, failed = validate_manifest(spec)
        assert failed
        assert report["undersized_pcap_files"] == ["1.pcap"]


def test_validate_manifest_reports_duplicate_segment_ids() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        touch(spec.raw_dir / "out_00001_20221205162606.pcap")
        report, failed = validate_manifest(spec)
        assert failed
        assert report["duplicate_segment_ids"] == [1]


if __name__ == "__main__":
    test_validate_manifest_accepts_parameterized_dataset()
    test_validate_manifest_reports_missing_segment()
    test_validate_manifest_rejects_empty_dataset_files()
    test_validate_manifest_reports_duplicate_segment_ids()
