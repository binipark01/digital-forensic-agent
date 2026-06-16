from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from dfatool import __version__
from dfatool.mft import build_timeline_events as build_mft_timeline_events
from dfatool.mft import dump_record, parse_mft_file
from dfatool.mft.parser import MftParseError
from dfatool.usn import build_timeline_events as build_usn_timeline_events
from dfatool.usn import parse_usn_file
from dfatool.usn.binary import UsnParseError


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 2
    try:
        return args.handler(args)
    except (MftParseError, UsnParseError) as exc:
        print(f"dfatool: {exc}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfatool", description="First-party forensic parsing toolkit")
    parser.add_argument("--version", action="version", version=f"dfatool {__version__}")
    subparsers = parser.add_subparsers(dest="artifact")

    mft_parser = subparsers.add_parser("mft", help="NTFS $MFT commands")
    mft_subparsers = mft_parser.add_subparsers(dest="command")

    parse_parser = mft_subparsers.add_parser("parse", help="Parse MFT records")
    parse_parser.add_argument("--input", required=True, type=Path, help="Path to an extracted $MFT file")
    parse_parser.add_argument("--json", dest="json_path", type=Path, help="Output JSONL records")
    parse_parser.add_argument("--csv", dest="csv_path", type=Path, help="Output CSV records")
    parse_parser.set_defaults(handler=_parse_mft)

    timeline_parser = mft_subparsers.add_parser("timeline", help="Emit normalized MFT timeline events")
    timeline_parser.add_argument("--input", required=True, type=Path, help="Path to an extracted $MFT file")
    timeline_parser.add_argument("--output", required=True, type=Path, help="Output JSONL timeline")
    timeline_parser.set_defaults(handler=_timeline_mft)

    dump_parser = mft_subparsers.add_parser("dump-record", help="Dump one parsed MFT record as JSON")
    dump_parser.add_argument("--input", required=True, type=Path, help="Path to an extracted $MFT file")
    dump_parser.add_argument("--entry", required=True, type=int, help="MFT entry number")
    dump_parser.set_defaults(handler=_dump_record)

    usn_parser = subparsers.add_parser("usn", help="NTFS $UsnJrnl:$J commands")
    usn_subparsers = usn_parser.add_subparsers(dest="command")

    usn_parse = usn_subparsers.add_parser("parse", help="Parse USN journal records")
    usn_parse.add_argument("--input", required=True, type=Path, help="Path to an extracted $UsnJrnl:$J file")
    usn_parse.add_argument("--json", dest="json_path", type=Path, help="Output JSONL records")
    usn_parse.add_argument("--csv", dest="csv_path", type=Path, help="Output CSV records")
    usn_parse.set_defaults(handler=_parse_usn)

    usn_timeline = usn_subparsers.add_parser("timeline", help="Emit normalized USN timeline events")
    usn_timeline.add_argument("--input", required=True, type=Path, help="Path to an extracted $UsnJrnl:$J file")
    usn_timeline.add_argument("--output", required=True, type=Path, help="Output JSONL timeline")
    usn_timeline.set_defaults(handler=_timeline_usn)
    return parser


def _parse_mft(args: argparse.Namespace) -> int:
    result = parse_mft_file(args.input)
    if not args.json_path and not args.csv_path:
        for record in result.records:
            print(json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True))
        return 0

    if args.json_path:
        _write_jsonl(args.json_path, [record.to_dict() for record in result.records])
    if args.csv_path:
        _write_record_csv(args.csv_path, result.records)
    return 0


def _timeline_mft(args: argparse.Namespace) -> int:
    result = parse_mft_file(args.input)
    _write_jsonl(args.output, build_mft_timeline_events(result))
    return 0


def _dump_record(args: argparse.Namespace) -> int:
    result = parse_mft_file(args.input)
    print(json.dumps(dump_record(result, args.entry), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _parse_usn(args: argparse.Namespace) -> int:
    result = parse_usn_file(args.input)
    if not args.json_path and not args.csv_path:
        for record in result.records:
            print(json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True))
        return 0

    if args.json_path:
        _write_jsonl(args.json_path, [record.to_dict() for record in result.records])
    if args.csv_path:
        _write_usn_record_csv(args.csv_path, result.records)
    return 0


def _timeline_usn(args: argparse.Namespace) -> int:
    result = parse_usn_file(args.input)
    _write_jsonl(args.output, build_usn_timeline_events(result))
    return 0


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def _write_record_csv(path: Path, records: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "entry",
        "sequence_number",
        "record_offset",
        "usa_offset",
        "usa_count",
        "lsn",
        "hard_link_count",
        "flags",
        "next_attribute_id",
        "active",
        "deleted",
        "is_directory",
        "path",
        "parent_entry",
        "parent_sequence",
        "si_created",
        "si_modified",
        "si_mft_modified",
        "si_accessed",
        "file_names",
        "data_attributes",
        "warnings",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            si = record.standard_information[0].timestamps.to_dict() if record.standard_information else {}
            file_name = record.file_names[0] if record.file_names else None
            writer.writerow(
                {
                    "entry": record.entry,
                    "sequence_number": record.sequence_number,
                    "record_offset": record.record_offset,
                    "usa_offset": record.usa_offset,
                    "usa_count": record.usa_count,
                    "lsn": record.lsn,
                    "hard_link_count": record.hard_link_count,
                    "flags": record.flags,
                    "next_attribute_id": record.next_attribute_id,
                    "active": record.active,
                    "deleted": record.is_deleted,
                    "is_directory": record.is_directory,
                    "path": record.path,
                    "parent_entry": file_name.parent_reference.entry if file_name else "",
                    "parent_sequence": file_name.parent_reference.sequence if file_name else "",
                    "si_created": si.get("created"),
                    "si_modified": si.get("modified"),
                    "si_mft_modified": si.get("mft_modified"),
                    "si_accessed": si.get("accessed"),
                    "file_names": json.dumps([item.to_dict() for item in record.file_names], ensure_ascii=False),
                    "data_attributes": json.dumps(
                        [item.to_dict() for item in record.data_attributes], ensure_ascii=False
                    ),
                    "warnings": json.dumps(record.warnings, ensure_ascii=False),
                }
            )


def _write_usn_record_csv(path: Path, records: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "usn",
        "file_reference_number",
        "parent_file_reference_number",
        "timestamp",
        "raw_reason",
        "reason_flags",
        "file_attributes",
        "file_name",
        "record_offset",
        "record_length",
        "warnings",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "usn": record.usn,
                    "file_reference_number": record.file_reference_number,
                    "parent_file_reference_number": record.parent_file_reference_number,
                    "timestamp": record.timestamp,
                    "raw_reason": record.raw_reason,
                    "reason_flags": json.dumps(record.reason_flags, ensure_ascii=False),
                    "file_attributes": record.file_attributes,
                    "file_name": record.file_name,
                    "record_offset": record.record_offset,
                    "record_length": record.record_length,
                    "warnings": json.dumps(record.warnings, ensure_ascii=False),
                }
            )


if __name__ == "__main__":
    raise SystemExit(main())
