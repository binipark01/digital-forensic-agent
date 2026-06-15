from __future__ import annotations

import struct
from datetime import UTC, datetime


RECORD_SIZE = 1024
SECTOR_SIZE = 512
FIRST_ATTR_OFFSET = 0x38
USA_OFFSET = 0x30


def synthetic_mft_bytes() -> bytes:
    return b"".join(
        [
            build_record(0, 1, True, True, 0, 1, "."),
            build_record(1, 3, True, True, 0, 1, "Users"),
            build_record(2, 7, True, False, 1, 3, "report.txt", data_streams=[("", 128)]),
            build_record(
                3,
                9,
                False,
                False,
                1,
                3,
                "deleted.txt",
                data_streams=[("", 64), ("Zone.Identifier", 26)],
            ),
        ]
    )


def build_record(
    entry: int,
    sequence: int,
    active: bool,
    directory: bool,
    parent_entry: int,
    parent_sequence: int,
    name: str,
    *,
    data_streams: list[tuple[str, int]] | None = None,
) -> bytes:
    record = bytearray(RECORD_SIZE)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 0x04, USA_OFFSET, 3)
    struct.pack_into("<Q", record, 0x08, 0)
    struct.pack_into("<HH", record, 0x10, sequence, 1)
    struct.pack_into("<H", record, 0x14, FIRST_ATTR_OFFSET)
    flags = (0x01 if active else 0) | (0x02 if directory else 0)
    struct.pack_into("<H", record, 0x16, flags)
    struct.pack_into("<I", record, 0x1C, RECORD_SIZE)
    struct.pack_into("<Q", record, 0x20, 0)
    struct.pack_into("<H", record, 0x28, 6)
    struct.pack_into("<I", record, 0x2C, entry)

    attrs = [
        resident_attr(0x10, standard_information_content(entry), attr_id=0),
        resident_attr(0x30, file_name_content(parent_entry, parent_sequence, name, directory), attr_id=1),
    ]
    for index, (stream_name, size) in enumerate(data_streams or [], start=2):
        attrs.append(resident_attr(0x80, b"x" * size, name=stream_name, attr_id=index))

    cursor = FIRST_ATTR_OFFSET
    for attr in attrs:
        record[cursor : cursor + len(attr)] = attr
        cursor += len(attr)
    struct.pack_into("<I", record, cursor, 0xFFFFFFFF)
    used_size = align8(cursor + 4)
    struct.pack_into("<I", record, 0x18, used_size)

    apply_usa(record)
    return bytes(record)


def standard_information_content(seed: int) -> bytes:
    created = filetime(datetime(2026, 1, 1, 0, 0, seed, tzinfo=UTC))
    modified = filetime(datetime(2026, 1, 2, 0, 0, seed, tzinfo=UTC))
    mft_modified = filetime(datetime(2026, 1, 3, 0, 0, seed, tzinfo=UTC))
    accessed = filetime(datetime(2026, 1, 4, 0, 0, seed, tzinfo=UTC))
    return struct.pack("<QQQQI", created, modified, mft_modified, accessed, 0x20).ljust(48, b"\x00")


def file_name_content(parent_entry: int, parent_sequence: int, name: str, directory: bool) -> bytes:
    name_bytes = name.encode("utf-16le")
    created = filetime(datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC))
    modified = filetime(datetime(2026, 2, 2, 0, 0, 0, tzinfo=UTC))
    mft_modified = filetime(datetime(2026, 2, 3, 0, 0, 0, tzinfo=UTC))
    accessed = filetime(datetime(2026, 2, 4, 0, 0, 0, tzinfo=UTC))
    parent_ref = (parent_sequence << 48) | parent_entry
    flags = 0x10000000 if directory else 0x20
    return (
        struct.pack(
            "<QQQQQQQIIBB",
            parent_ref,
            created,
            modified,
            mft_modified,
            accessed,
            4096,
            123,
            flags,
            0,
            len(name),
            1,
        )
        + name_bytes
    )


def resident_attr(type_code: int, content: bytes, *, name: str = "", attr_id: int) -> bytes:
    name_bytes = name.encode("utf-16le")
    name_offset = 24 if name_bytes else 0
    content_offset = align8(24 + len(name_bytes))
    total_length = align8(content_offset + len(content))
    attr = bytearray(total_length)
    struct.pack_into(
        "<IIBBHHH",
        attr,
        0,
        type_code,
        total_length,
        0,
        len(name),
        name_offset,
        0,
        attr_id,
    )
    struct.pack_into("<IHBB", attr, 16, len(content), content_offset, 0, 0)
    if name_bytes:
        attr[name_offset : name_offset + len(name_bytes)] = name_bytes
    attr[content_offset : content_offset + len(content)] = content
    return bytes(attr)


def apply_usa(record: bytearray) -> None:
    usn = b"\xAA\x55"
    record[USA_OFFSET : USA_OFFSET + 2] = usn
    for index in range(1, 3):
        sector_end = index * SECTOR_SIZE - 2
        saved_offset = USA_OFFSET + index * 2
        record[saved_offset : saved_offset + 2] = record[sector_end : sector_end + 2]
        record[sector_end : sector_end + 2] = usn


def filetime(value: datetime) -> int:
    ntfs_epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return int((value - ntfs_epoch).total_seconds() * 10_000_000)


def align8(value: int) -> int:
    return (value + 7) & ~7
