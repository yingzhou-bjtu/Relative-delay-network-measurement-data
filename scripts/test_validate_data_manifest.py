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
    manifest_spec_from_args,
    parse_csv_names,
    resolve_report_path,
    validate_manifest,
    write_report_json,
)


HOME = Path.home().resolve()


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


def test_manifest_spec_rejects_dataset_dirs_outside_root() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        args = argparse.Namespace(
            root=root,
            dns_dir="../dns",
            raw_dir=DEFAULT_RAW_DIR,
            expected_dns_files=("ip.xlsx", "url.xlsx"),
            representative_pcaps=("1.pcap",),
            expected_segments=0,
            min_file_bytes=1,
        )
        try:
            manifest_spec_from_args(args)
        except ValueError as exc:
            assert "under root" in str(exc)
        else:
            raise AssertionError("dns_dir outside root was accepted")


def test_manifest_spec_rejects_file_root() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root_file = Path(tmp) / "dataset.txt"
        root_file.write_text("not a directory\n", encoding="utf-8")
        args = argparse.Namespace(
            root=root_file,
            dns_dir=DEFAULT_DNS_DIR,
            raw_dir=DEFAULT_RAW_DIR,
            expected_dns_files=("ip.xlsx", "url.xlsx"),
            representative_pcaps=("1.pcap",),
            expected_segments=0,
            min_file_bytes=1,
        )
        try:
            manifest_spec_from_args(args)
        except ValueError as exc:
            assert "root is not a directory" in str(exc)
        else:
            raise AssertionError("file root was accepted")


def test_manifest_spec_expands_user_root() -> None:
    args = argparse.Namespace(
        root=Path("~"),
        dns_dir=DEFAULT_DNS_DIR,
        raw_dir=DEFAULT_RAW_DIR,
        expected_dns_files=("ip.xlsx", "url.xlsx"),
        representative_pcaps=("1.pcap",),
        expected_segments=0,
        min_file_bytes=1,
    )
    spec = manifest_spec_from_args(args)
    assert spec.root == HOME
    assert spec.dns_dir == HOME / DEFAULT_DNS_DIR


def test_manifest_spec_expands_user_dataset_dirs_under_root() -> None:
    args = argparse.Namespace(
        root=Path("~"),
        dns_dir=str(Path("~") / DEFAULT_DNS_DIR),
        raw_dir=DEFAULT_RAW_DIR,
        expected_dns_files=("ip.xlsx", "url.xlsx"),
        representative_pcaps=("1.pcap",),
        expected_segments=0,
        min_file_bytes=1,
    )
    spec = manifest_spec_from_args(args)
    assert spec.dns_dir == HOME / DEFAULT_DNS_DIR


def test_resolve_report_path_rejects_dataset_file_overwrite() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        try:
            resolve_report_path(spec.raw_dir / "report.json", spec)
        except ValueError as exc:
            assert "raw packet-capture" in str(exc)
        else:
            raise AssertionError("json_out accepted a raw data directory path")


def test_resolve_report_path_rejects_non_json_suffix() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        try:
            resolve_report_path(Path(tmp) / "results" / "report.txt", spec)
        except ValueError as exc:
            assert "must end with .json" in str(exc)
        else:
            raise AssertionError("json_out accepted a non-json suffix")


def test_resolve_report_path_accepts_artifact_json() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        spec = make_dataset(Path(tmp))
        path = resolve_report_path(Path(tmp) / "results" / "report.json", spec)
        assert path.name == "report.json"


def test_write_report_json_replaces_report_without_temp_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "results" / "report.json"
        path.parent.mkdir()
        path.write_text('{"old": true}\n', encoding="utf-8")

        write_report_json(path, '{"new": true}')

        assert path.read_text(encoding="utf-8") == '{"new": true}\n'
        assert not list(path.parent.glob(".report.json.*.tmp"))


if __name__ == "__main__":
    for name, test_func in sorted(globals().items()):
        if name.startswith("test_") and callable(test_func):
            test_func()
