from __future__ import annotations

import struct
from pathlib import Path

from dfatool.usn.binary import UsnParseError, parse_record, sha256_file, u32, u16
from dfatool.usn.constants import MAX_RECORD_SIZE, USN_RECORD_V2_HEADER_SIZE, USN_RECORD_V3_HEADER_SIZE
from dfatool.usn.models import UsnParseResult, UsnRecord


def parse_usn_file(
    path: str | Path,
    *,
    artifact_hash: str | None = None,
    max_records: int = 1_000_000,
    max_warnings: int = 10_000,
    max_record_size: int = MAX_RECORD_SIZE,
) -> UsnParseResult:
    artifact_path = Path(path)
    digest = artifact_hash or sha256_file(artifact_path)
    records: list[UsnRecord] = []
    warnings: list[str] = []
    processed_records = 0

    with artifact_path.open("rb") as handle:
        record_offset = 0
        while True:
            length_prefix = handle.read(4)
            if not length_prefix:
                break
            if len(length_prefix) < 4:
                _append_warning(warnings, f"trailing partial USN record length at offset {record_offset}", max_warnings)
                break
            record_length = u32(length_prefix, 0)
            if record_length == 0:
                _append_warning(warnings, f"zero USN record length at offset {record_offset}", max_warnings)
                break
            if record_length > max_record_size:
                _append_warning(
                    warnings,
                    f"USN record length {record_length} exceeds parser limit at offset {record_offset}",
                    max_warnings,
                )
                break
            body = handle.read(record_length - 4) if record_length >= 4 else b""
            if len(body) != record_length - 4:
                _append_warning(warnings, f"trailing partial USN record at offset {record_offset}", max_warnings)
                break
            if processed_records >= max_records:
                _append_warning(warnings, f"record processing limit reached at {max_records} records", max_warnings)
                break
            processed_records += 1
            record = _parse_record_safely(length_prefix + body, record_offset, warnings, max_warnings)
            if record:
                records.append(record)
            record_offset += record_length

    if not records:
        warnings.append("no valid USN records found")
    return UsnParseResult(
        artifact_path=str(artifact_path),
        artifact_hash=digest,
        records=records,
        warnings=warnings,
    )


def can_parse_usn_file(path: Path) -> bool:
    if not path.exists() or path.stat().st_size < USN_RECORD_V2_HEADER_SIZE:
        return False
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
    except OSError:
        return False
    if len(header) < 8:
        return False
    record_length = u32(header, 0)
    major_version = u16(header, 4)
    minimum = _minimum_header_size(major_version)
    return minimum is not None and minimum <= record_length <= min(path.stat().st_size, MAX_RECORD_SIZE)


def _parse_record_safely(
    data: bytes,
    record_offset: int,
    warnings: list[str],
    max_warnings: int,
) -> UsnRecord | None:
    try:
        return parse_record(data, record_offset=record_offset)
    except (UsnParseError, struct.error) as exc:
        _append_warning(warnings, f"failed to parse USN record at offset {record_offset}: {exc}", max_warnings)
        return None


def _minimum_header_size(major_version: int) -> int | None:
    match major_version:
        case 2:
            return USN_RECORD_V2_HEADER_SIZE
        case 3:
            return USN_RECORD_V3_HEADER_SIZE
        case _:
            return None


def _append_warning(warnings: list[str], warning: str, max_warnings: int) -> None:
    if len(warnings) < max_warnings:
        warnings.append(warning)
        return
    if len(warnings) == max_warnings:
        warnings.append("parser warning limit reached; additional warnings suppressed")
