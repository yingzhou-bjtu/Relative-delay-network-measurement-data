#!/usr/bin/env python3
"""Lightweight checks for the dataset manifest validator."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from validate_data_manifest import (
    DEFAULT_DNS_DIR,
    DEFAULT_RAW_DIR,
    ManifestSpec,
    parse_csv_names,
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
        assert report["first_segment_timestamp"] == "20221205162552"
        assert report["last_segment_timestamp"] == "20221205162605"


def test_validate_manifest_reports_missing_segment() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        (spec.raw_dir / "out_00001_20221205162605.pcap").unlink()
        report, failed = validate_manifest(spec)
        assert failed
        assert report["missing_segments"] == [1]


def test_validate_manifest_reports_missing_representative_pcap() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        (spec.raw_dir / "2.pcap").unlink()
        report, failed = validate_manifest(spec)
        assert failed
        assert report["missing_representative_pcaps"] == ["2.pcap"]


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


def test_validate_manifest_reports_duplicate_segment_timestamps() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        touch(spec.raw_dir / "out_00002_20221205162605.pcap")
        report, failed = validate_manifest(spec)
        assert failed
        assert report["duplicate_segment_timestamps"] == ["20221205162605"]


def test_validate_manifest_reports_non_monotonic_segment_timestamps() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        (spec.raw_dir / "out_00001_20221205162605.pcap").unlink()
        touch(spec.raw_dir / "out_00001_20221205162500.pcap")
        report, failed = validate_manifest(spec)
        assert failed
        assert report["non_monotonic_segment_timestamps"] == [
            "out_00001_20221205162500.pcap"
        ]


def test_parse_csv_names_rejects_duplicates() -> None:
    try:
        parse_csv_names("1.pcap,2.pcap,1.pcap")
    except argparse.ArgumentTypeError as exc:
        assert "duplicate comma-separated names" in str(exc)
    else:
        raise AssertionError("duplicate CSV names were accepted")


def test_parse_csv_names_rejects_paths() -> None:
    try:
        parse_csv_names("1.pcap,../outside.pcap")
    except argparse.ArgumentTypeError as exc:
        assert "file names, not paths" in str(exc)
    else:
        raise AssertionError("path-like CSV names were accepted")


def test_manifest_spec_rejects_path_like_expected_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        try:
            ManifestSpec(
                root=root,
                dns_dir=root / DEFAULT_DNS_DIR,
                raw_dir=root / DEFAULT_RAW_DIR,
                expected_dns_files=("ip.xlsx", "../url.xlsx"),
                representative_pcaps=("1.pcap",),
                expected_segments=0,
                min_file_bytes=1,
            )
        except ValueError as exc:
            assert "expected_dns_files" in str(exc)
            assert "file names, not paths" in str(exc)
        else:
            raise AssertionError("path-like expected DNS file was accepted")


if __name__ == "__main__":
    test_validate_manifest_accepts_parameterized_dataset()
    test_validate_manifest_reports_missing_segment()
    test_validate_manifest_reports_missing_representative_pcap()
    test_validate_manifest_rejects_empty_dataset_files()
    test_validate_manifest_reports_duplicate_segment_ids()
    test_validate_manifest_reports_duplicate_segment_timestamps()
    test_validate_manifest_reports_non_monotonic_segment_timestamps()
    test_parse_csv_names_rejects_duplicates()
    test_parse_csv_names_rejects_paths()
    test_manifest_spec_rejects_path_like_expected_files()
