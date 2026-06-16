from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from dfatool.mft.binary import MftParseError, sha256_file
from dfatool.mft.models import MftParseResult, MftRecord
from dfatool.mft.paths import reconstruct_paths
from dfatool.mft.records import parse_record
from dfatool.mft.timeline import build_timeline_events


def parse_mft_file(
    path: str | Path,
    *,
    record_size: int = 1024,
    sector_size: int = 512,
    artifact_hash: str | None = None,
    max_records: int = 250_000,
    max_warnings: int = 10_000,
) -> MftParseResult:
    artifact_path = Path(path)
    digest = artifact_hash or sha256_file(artifact_path)
    records: list[MftRecord] = []
    warnings: list[str] = []
    processed_records = 0

    with artifact_path.open("rb") as handle:
        index = 0
        while True:
            chunk = handle.read(record_size)
            if not chunk:
                break
            if len(chunk) < record_size:
                _warn_partial_record(chunk, index, record_size, warnings)
                break
            if processed_records >= max_records:
                _append_warning(
                    warnings,
                    f"record processing limit reached at {max_records} records",
                    max_warnings,
                )
                break
            processed_records += 1
            if not chunk.strip(b"\x00"):
                index += 1
                continue
            if chunk[:4] != b"FILE":
                _append_warning(
                    warnings,
                    f"invalid FILE signature at offset {index * record_size}: {chunk[:4]!r}",
                    max_warnings,
                )
                index += 1
                continue
            record = _parse_record_safely(chunk, index, record_size, sector_size, warnings, max_warnings)
            if record:
                records.append(record)
            index += 1

    reconstruct_paths(records)
    if not records:
        warnings.append("no valid MFT FILE records found")
    return MftParseResult(
        artifact_path=str(artifact_path),
        artifact_hash=digest,
        record_size=record_size,
        sector_size=sector_size,
        records=records,
        warnings=warnings,
    )


def dump_record(result: MftParseResult, entry: int) -> dict[str, Any]:
    for record in result.records:
        if record.entry == entry:
            return {
                "artifact_hash": result.artifact_hash,
                "record_size": result.record_size,
                "sector_size": result.sector_size,
                "record": record.to_dict(),
            }
    raise MftParseError(f"MFT entry {entry} was not found")


def _parse_record_safely(
    chunk: bytes,
    index: int,
    record_size: int,
    sector_size: int,
    warnings: list[str],
    max_warnings: int,
) -> MftRecord | None:
    record_offset = index * record_size
    try:
        return parse_record(
            chunk,
            index=index,
            record_offset=record_offset,
            record_size=record_size,
            sector_size=sector_size,
        )
    except (MftParseError, struct.error) as exc:
        _append_warning(warnings, f"failed to parse record at offset {record_offset}: {exc}", max_warnings)
        return None


def _warn_partial_record(
    chunk: bytes,
    index: int,
    record_size: int,
    warnings: list[str],
) -> None:
    if chunk.strip(b"\x00"):
        warnings.append(f"trailing partial record at offset {index * record_size} has {len(chunk)} bytes")


def _append_warning(warnings: list[str], warning: str, max_warnings: int) -> None:
    if len(warnings) < max_warnings:
        warnings.append(warning)
        return
    if len(warnings) == max_warnings:
        warnings.append("parser warning limit reached; additional warnings suppressed")
