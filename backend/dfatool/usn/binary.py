from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dfatool.usn.constants import REASON_FLAGS, USN_RECORD_V2_HEADER_SIZE, USN_RECORD_V3_HEADER_SIZE
from dfatool.usn.models import UsnFileReference, UsnRecord

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


class UsnParseError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_record(data: bytes, *, record_offset: int) -> UsnRecord:
    record_warnings: list[str] = []
    record_length = u32(data, 0)
    major_version = u16(data, 4)
    minor_version = u16(data, 6)
    if record_length != len(data):
        record_warnings.append(f"record length header {record_length} differs from read length {len(data)}")

    match major_version:
        case 2:
            return _parse_v2(data, record_offset, record_warnings)
        case 3:
            return _parse_v3(data, record_offset, record_warnings)
        case _:
            raise UsnParseError(f"unsupported USN_RECORD major version {major_version}")


def decode_reason_flags(raw_reason: int) -> list[str]:
    flags = [name for bit, name in REASON_FLAGS if raw_reason & bit]
    known_mask = 0
    for bit, _name in REASON_FLAGS:
        known_mask |= bit
    unknown = raw_reason & ~known_mask
    if unknown:
        flags.append(f"UNKNOWN_0x{unknown:08X}")
    return flags


def filetime_to_iso(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        return (NTFS_EPOCH + timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError):
        return None


def parse_file_reference(raw: int, *, major_version: int) -> UsnFileReference:
    if major_version == 2:
        return UsnFileReference(entry=raw & 0x0000FFFFFFFFFFFF, sequence=(raw >> 48) & 0xFFFF, raw=raw)
    return UsnFileReference(entry=None, sequence=None, raw=raw)


def decode_utf16_name(data: bytes, *, offset: int, length: int, warnings: list[str]) -> str:
    if length <= 0:
        return ""
    if offset + length > len(data):
        warnings.append("file name range is outside the USN record")
        return ""
    if length % 2:
        warnings.append("file name length is not UTF-16 aligned")
    return data[offset : offset + length].decode("utf-16le", errors="replace").rstrip("\x00")


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def i64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<q", data, offset)[0]


def u128(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 16], "little", signed=False)


def _parse_v2(data: bytes, record_offset: int, warnings: list[str]) -> UsnRecord:
    _require_minimum_size(data, USN_RECORD_V2_HEADER_SIZE)
    file_reference_number = u64(data, 8)
    parent_file_reference_number = u64(data, 16)
    file_name_length = u16(data, 56)
    file_name_offset = u16(data, 58)
    return UsnRecord(
        record_length=u32(data, 0),
        major_version=2,
        minor_version=u16(data, 6),
        file_reference_number=file_reference_number,
        parent_file_reference_number=parent_file_reference_number,
        file_reference=parse_file_reference(file_reference_number, major_version=2),
        parent_file_reference=parse_file_reference(parent_file_reference_number, major_version=2),
        usn=i64(data, 24),
        timestamp=filetime_to_iso(u64(data, 32)),
        raw_reason=u32(data, 40),
        reason_flags=decode_reason_flags(u32(data, 40)),
        source_info=u32(data, 44),
        security_id=u32(data, 48),
        file_attributes=u32(data, 52),
        file_name_length=file_name_length,
        file_name_offset=file_name_offset,
        file_name=decode_utf16_name(data, offset=file_name_offset, length=file_name_length, warnings=warnings),
        record_offset=record_offset,
        warnings=warnings,
    )


def _parse_v3(data: bytes, record_offset: int, warnings: list[str]) -> UsnRecord:
    _require_minimum_size(data, USN_RECORD_V3_HEADER_SIZE)
    file_reference_number = u128(data, 8)
    parent_file_reference_number = u128(data, 24)
    file_name_length = u16(data, 72)
    file_name_offset = u16(data, 74)
    return UsnRecord(
        record_length=u32(data, 0),
        major_version=3,
        minor_version=u16(data, 6),
        file_reference_number=file_reference_number,
        parent_file_reference_number=parent_file_reference_number,
        file_reference=parse_file_reference(file_reference_number, major_version=3),
        parent_file_reference=parse_file_reference(parent_file_reference_number, major_version=3),
        usn=i64(data, 40),
        timestamp=filetime_to_iso(u64(data, 48)),
        raw_reason=u32(data, 56),
        reason_flags=decode_reason_flags(u32(data, 56)),
        source_info=u32(data, 60),
        security_id=u32(data, 64),
        file_attributes=u32(data, 68),
        file_name_length=file_name_length,
        file_name_offset=file_name_offset,
        file_name=decode_utf16_name(data, offset=file_name_offset, length=file_name_length, warnings=warnings),
        record_offset=record_offset,
        warnings=warnings,
    )


def _require_minimum_size(data: bytes, minimum: int) -> None:
    if len(data) < minimum:
        raise UsnParseError(f"record length {len(data)} is too small for USN_RECORD header {minimum}")
