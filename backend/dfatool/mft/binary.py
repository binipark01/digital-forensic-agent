from __future__ import annotations

import hashlib
import struct
from datetime import timedelta
from pathlib import Path

from dfatool.mft.constants import NTFS_EPOCH
from dfatool.mft.models import FileReference


class MftParseError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_file_reference(raw: int) -> FileReference:
    return FileReference(entry=raw & 0x0000FFFFFFFFFFFF, sequence=(raw >> 48) & 0xFFFF, raw=raw)


def filetime_to_iso(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        return (NTFS_EPOCH + timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError):
        return None


def apply_usa_fixup(raw_record: bytes, *, sector_size: int, warnings: list[str]) -> bytes:
    data = bytearray(raw_record)
    if len(data) < 8:
        warnings.append("record too short for USA fixup header")
        return bytes(data)

    usa_offset = u16(data, 0x04)
    usa_count = u16(data, 0x06)
    if usa_count <= 1:
        warnings.append("USA fixup count is too small")
        return bytes(data)

    usa_end = usa_offset + usa_count * 2
    if usa_offset < 8 or usa_end > len(data):
        warnings.append("USA fixup array is outside the record")
        return bytes(data)

    usn = data[usa_offset : usa_offset + 2]
    for index in range(1, usa_count):
        sector_end = index * sector_size - 2
        if sector_end + 2 > len(data):
            warnings.append(f"USA fixup sector {index} is outside the record")
            continue
        replacement = data[usa_offset + index * 2 : usa_offset + index * 2 + 2]
        if data[sector_end : sector_end + 2] != usn:
            warnings.append(f"USA sequence mismatch at sector {index}")
        data[sector_end : sector_end + 2] = replacement
    return bytes(data)


def decode_utf16(data: bytes, offset: int, length: int) -> str:
    if length <= 0:
        return ""
    raw = data[offset : offset + length]
    return raw.decode("utf-16le", errors="replace").rstrip("\x00")


def align8(value: int) -> int:
    return (value + 7) & ~7


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]
