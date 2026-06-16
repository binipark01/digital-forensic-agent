from __future__ import annotations

import struct
from datetime import UTC, datetime

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_CLOSE = 0x80000000

FILE_ATTRIBUTE_ARCHIVE = 0x20
FILE_ATTRIBUTE_DIRECTORY = 0x10


def synthetic_usn_bytes(*, include_malformed: bool = False) -> bytes:
    records = [
        usn_record_v2(
            file_reference_number=file_reference(42, 7),
            parent_file_reference_number=file_reference(5, 1),
            usn=100,
            timestamp=datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC),
            reason=USN_REASON_FILE_CREATE,
            file_attributes=FILE_ATTRIBUTE_ARCHIVE,
            file_name="created.txt",
        ),
        usn_record_v2(
            file_reference_number=file_reference(43, 7),
            parent_file_reference_number=file_reference(5, 1),
            usn=120,
            timestamp=datetime(2026, 3, 1, 0, 1, 0, tzinfo=UTC),
            reason=USN_REASON_DATA_EXTEND | USN_REASON_CLOSE,
            file_attributes=FILE_ATTRIBUTE_ARCHIVE,
            file_name="modified.bin",
        ),
        usn_record_v2(
            file_reference_number=file_reference(44, 9),
            parent_file_reference_number=file_reference(5, 1),
            usn=130,
            timestamp=datetime(2026, 3, 1, 0, 2, 0, tzinfo=UTC),
            reason=USN_REASON_RENAME_OLD_NAME,
            file_attributes=FILE_ATTRIBUTE_ARCHIVE,
            file_name="old-name.docx",
        ),
        usn_record_v2(
            file_reference_number=file_reference(44, 9),
            parent_file_reference_number=file_reference(5, 1),
            usn=140,
            timestamp=datetime(2026, 3, 1, 0, 2, 1, tzinfo=UTC),
            reason=USN_REASON_RENAME_NEW_NAME,
            file_attributes=FILE_ATTRIBUTE_ARCHIVE,
            file_name="new-name.docx",
        ),
        usn_record_v2(
            file_reference_number=file_reference(45, 2),
            parent_file_reference_number=file_reference(5, 1),
            usn=150,
            timestamp=datetime(2026, 3, 1, 0, 3, 0, tzinfo=UTC),
            reason=USN_REASON_FILE_DELETE | USN_REASON_SECURITY_CHANGE,
            file_attributes=FILE_ATTRIBUTE_DIRECTORY,
            file_name="deleted-dir",
        ),
    ]
    if include_malformed:
        records.insert(1, malformed_short_record())
    return b"".join(records)


def usn_record_v2(
    *,
    file_reference_number: int,
    parent_file_reference_number: int,
    usn: int,
    timestamp: datetime,
    reason: int,
    file_attributes: int,
    file_name: str,
    source_info: int = 0,
    security_id: int = 501,
    major_version: int = 2,
    minor_version: int = 0,
) -> bytes:
    name_bytes = file_name.encode("utf-16le")
    file_name_offset = 60
    record_length = align8(file_name_offset + len(name_bytes))
    header = struct.pack(
        "<IHHQQqQIIIIHH",
        record_length,
        major_version,
        minor_version,
        file_reference_number,
        parent_file_reference_number,
        usn,
        filetime(timestamp),
        reason,
        source_info,
        security_id,
        file_attributes,
        len(name_bytes),
        file_name_offset,
    )
    return header + name_bytes + (b"\x00" * (record_length - file_name_offset - len(name_bytes)))


def malformed_short_record() -> bytes:
    return struct.pack("<IHH", 8, 2, 0)


def file_reference(entry: int, sequence: int) -> int:
    return (sequence << 48) | entry


def filetime(value: datetime) -> int:
    return int((value - NTFS_EPOCH).total_seconds() * 10_000_000)


def align8(value: int) -> int:
    return (value + 7) & ~7
