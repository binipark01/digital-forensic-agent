from __future__ import annotations

from dfatool.mft.attributes import parse_attributes
from dfatool.mft.binary import MftParseError, apply_usa_fixup, parse_file_reference, u16, u32, u64
from dfatool.mft.models import MftRecord


def parse_record(
    raw_record: bytes,
    *,
    index: int,
    record_offset: int,
    record_size: int,
    sector_size: int,
) -> MftRecord | None:
    warnings: list[str] = []
    if raw_record[:4] != b"FILE":
        if raw_record.strip(b"\x00"):
            warnings.append(f"invalid FILE signature at offset {record_offset}: {raw_record[:4]!r}")
        return None

    fixed_record = apply_usa_fixup(raw_record, sector_size=sector_size, warnings=warnings)
    if len(fixed_record) < 48:
        raise MftParseError(f"record at offset {record_offset} is too small")

    base_reference_raw = u64(fixed_record, 0x20)
    flags = u16(fixed_record, 0x16)
    header_record_number = u32(fixed_record, 0x2C) if len(fixed_record) >= 0x30 else index
    record = MftRecord(
        entry=header_record_number if header_record_number != 0 or index == 0 else index,
        sequence_number=u16(fixed_record, 0x10),
        record_offset=record_offset,
        usa_offset=u16(raw_record, 0x04),
        usa_count=u16(raw_record, 0x06),
        lsn=u64(fixed_record, 0x08),
        hard_link_count=u16(fixed_record, 0x12),
        first_attribute_offset=u16(fixed_record, 0x14),
        flags=flags,
        used_size=u32(fixed_record, 0x18),
        allocated_size=u32(fixed_record, 0x1C),
        next_attribute_id=u16(fixed_record, 0x28),
        active=bool(flags & 0x01),
        is_directory=bool(flags & 0x02),
        base_file_reference=parse_file_reference(base_reference_raw) if base_reference_raw else None,
        warnings=warnings,
    )
    if record.allocated_size and record.allocated_size != record_size:
        record.warnings.append(
            f"record header allocated size {record.allocated_size} differs from parser record size {record_size}"
        )
    parse_attributes(fixed_record, record)
    return record
