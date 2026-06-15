from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from dfatool.mft.models import (
    AttributeSummary,
    DataAttribute,
    FileNameAttribute,
    FileReference,
    MftParseResult,
    MftRecord,
    StandardInformation,
    TimestampSet,
)


ATTRIBUTE_END = 0xFFFFFFFF
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

ATTRIBUTE_NAMES = {
    ATTR_STANDARD_INFORMATION: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    ATTR_FILE_NAME: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    ATTR_DATA: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0x100: "$LOGGED_UTILITY_STREAM",
}

FILE_NAME_NAMESPACES = {
    0: "POSIX",
    1: "Win32",
    2: "DOS",
    3: "Win32+DOS",
}


class MftParseError(ValueError):
    pass


def parse_mft_file(
    path: str | Path,
    *,
    record_size: int = 1024,
    sector_size: int = 512,
    artifact_hash: str | None = None,
) -> MftParseResult:
    artifact_path = Path(path)
    digest = artifact_hash or sha256_file(artifact_path)
    records: list[MftRecord] = []
    warnings: list[str] = []

    with artifact_path.open("rb") as handle:
        index = 0
        while True:
            chunk = handle.read(record_size)
            if not chunk:
                break
            if len(chunk) < record_size:
                if chunk.strip(b"\x00"):
                    warnings.append(
                        f"trailing partial record at offset {index * record_size} has {len(chunk)} bytes"
                    )
                break
            if not chunk.strip(b"\x00"):
                index += 1
                continue
            if chunk[:4] != b"FILE":
                warnings.append(f"invalid FILE signature at offset {index * record_size}: {chunk[:4]!r}")
                index += 1
                continue
            record = parse_record(
                chunk,
                index=index,
                record_offset=index * record_size,
                record_size=record_size,
                sector_size=sector_size,
            )
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


def build_timeline_events(result: MftParseResult) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in result.records:
        base_attributes = {
            "active": record.active,
            "is_deleted": record.is_deleted,
            "is_directory": record.is_directory,
            "data_streams": [stream.to_dict() for stream in record.data_attributes],
            "parser_warnings": list(record.warnings),
        }

        for si in record.standard_information:
            for field_name, timestamp in si.timestamps.to_dict().items():
                if not timestamp:
                    continue
                events.append(
                    _timeline_event(
                        result,
                        record,
                        timestamp,
                        f"si_{field_name}",
                        si.attribute_offset,
                        "$STANDARD_INFORMATION",
                        "high",
                        {
                            **base_attributes,
                            "timestamp_source": "$STANDARD_INFORMATION",
                            "timestamp_field": field_name,
                            "file_attributes": si.file_attributes,
                        },
                    )
                )

        for file_name in _timeline_file_names(record):
            for field_name, timestamp in file_name.timestamps.to_dict().items():
                if not timestamp:
                    continue
                events.append(
                    _timeline_event(
                        result,
                        record,
                        timestamp,
                        f"fn_{field_name}",
                        file_name.attribute_offset,
                        "$FILE_NAME",
                        "high",
                        {
                            **base_attributes,
                            "timestamp_source": "$FILE_NAME",
                            "timestamp_field": field_name,
                            "file_name_namespace": file_name.namespace_name,
                            "parent_reference": file_name.parent_reference.to_dict(),
                            "allocated_size": file_name.allocated_size,
                            "real_size": file_name.real_size,
                        },
                        path=file_name.full_path or record.path,
                    )
                )

        if record.is_deleted:
            anchor = _deleted_anchor(record)
            events.append(
                _timeline_event(
                    result,
                    record,
                    anchor["timestamp"],
                    "deleted_record_seen",
                    anchor["attribute_offset"],
                    anchor["attribute_type"],
                    "medium",
                    {
                        **base_attributes,
                        "timestamp_source": anchor["attribute_type"],
                        "reason": "MFT record in-use flag is unset",
                    },
                )
            )

        for data_attr in record.data_attributes:
            if not data_attr.is_ads:
                continue
            anchor = _metadata_anchor(record)
            events.append(
                _timeline_event(
                    result,
                    record,
                    anchor["timestamp"],
                    "ads_detected",
                    data_attr.attribute_offset,
                    "$DATA",
                    "medium",
                    {
                        **base_attributes,
                        "stream_name": data_attr.name,
                        "timestamp_source": anchor["attribute_type"],
                    },
                )
            )

    return events


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

    fixed_record = _apply_usa_fixup(raw_record, sector_size=sector_size, warnings=warnings)
    if len(fixed_record) < 48:
        raise MftParseError(f"record at offset {record_offset} is too small")

    usa_offset = _u16(raw_record, 0x04)
    usa_count = _u16(raw_record, 0x06)
    lsn = _u64(fixed_record, 0x08)
    sequence_number = _u16(fixed_record, 0x10)
    hard_link_count = _u16(fixed_record, 0x12)
    first_attribute_offset = _u16(fixed_record, 0x14)
    flags = _u16(fixed_record, 0x16)
    used_size = _u32(fixed_record, 0x18)
    allocated_size = _u32(fixed_record, 0x1C)
    base_reference_raw = _u64(fixed_record, 0x20)
    next_attribute_id = _u16(fixed_record, 0x28)
    header_record_number = _u32(fixed_record, 0x2C) if len(fixed_record) >= 0x30 else index
    entry = header_record_number if header_record_number != 0 or index == 0 else index

    record = MftRecord(
        entry=entry,
        sequence_number=sequence_number,
        record_offset=record_offset,
        usa_offset=usa_offset,
        usa_count=usa_count,
        lsn=lsn,
        hard_link_count=hard_link_count,
        first_attribute_offset=first_attribute_offset,
        flags=flags,
        used_size=used_size,
        allocated_size=allocated_size,
        next_attribute_id=next_attribute_id,
        active=bool(flags & 0x01),
        is_directory=bool(flags & 0x02),
        base_file_reference=parse_file_reference(base_reference_raw) if base_reference_raw else None,
        warnings=warnings,
    )

    _parse_attributes(fixed_record, record)
    return record


def reconstruct_paths(records: list[MftRecord]) -> None:
    records_by_entry = {record.entry: record for record in records}

    @lru_cache(maxsize=None)
    def build_path(entry: int, seen: tuple[int, ...] = ()) -> str:
        record = records_by_entry.get(entry)
        if not record:
            return f"/$OrphanFiles/{entry}"
        file_name = _preferred_file_name(record)
        if not file_name:
            return f"/$MFT/{entry}"
        parent_entry = file_name.parent_reference.entry
        if file_name.name in {"", "."} or parent_entry == entry:
            return "/"
        if entry in seen:
            record.warnings.append("parent reference loop while reconstructing path")
            return f"/$PathLoop/{entry}/{file_name.name}"
        parent = build_path(parent_entry, (*seen, entry)).rstrip("/")
        return f"{parent}/{file_name.name}" if parent else f"/{file_name.name}"

    for record in records:
        record.path = build_path(record.entry)
        for file_name in record.file_names:
            if file_name.name in {"", "."} or file_name.parent_reference.entry == record.entry:
                file_name.full_path = "/"
            else:
                parent = build_path(file_name.parent_reference.entry).rstrip("/")
                file_name.full_path = f"{parent}/{file_name.name}" if parent else f"/{file_name.name}"


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


def _apply_usa_fixup(raw_record: bytes, *, sector_size: int, warnings: list[str]) -> bytes:
    data = bytearray(raw_record)
    if len(data) < 8:
        warnings.append("record too short for USA fixup header")
        return bytes(data)

    usa_offset = _u16(data, 0x04)
    usa_count = _u16(data, 0x06)
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


def _parse_attributes(record_data: bytes, record: MftRecord) -> None:
    offset = record.first_attribute_offset
    limit = min(record.used_size if record.used_size > 0 else len(record_data), len(record_data))

    while offset + 16 <= limit:
        type_code = _u32(record_data, offset)
        if type_code == ATTRIBUTE_END:
            return

        length = _u32(record_data, offset + 4)
        if length < 16:
            record.warnings.append(f"attribute at offset {offset} has invalid length {length}")
            return
        if offset + length > len(record_data):
            record.warnings.append(f"attribute at offset {offset} extends beyond record")
            return

        nonresident = bool(record_data[offset + 8])
        name_length = record_data[offset + 9]
        name_offset = _u16(record_data, offset + 10)
        attribute_id = _u16(record_data, offset + 14)
        name = _decode_utf16(record_data, offset + name_offset, name_length * 2) if name_length else ""
        attr_name = ATTRIBUTE_NAMES.get(type_code, f"UNKNOWN_{type_code:#x}")

        summary = AttributeSummary(
            type_code=type_code,
            type_name=attr_name,
            offset=offset,
            length=length,
            resident=not nonresident,
            name=name,
            attribute_id=attribute_id,
        )

        content = b""
        content_offset: int | None = None
        content_size: int | None = None
        allocated_size: int | None = None
        initialized_size: int | None = None

        if nonresident:
            if length < 64:
                record.warnings.append(f"nonresident attribute at offset {offset} is too short")
            else:
                runlist_offset = _u16(record_data, offset + 32)
                allocated_size = _u64(record_data, offset + 40)
                content_size = _u64(record_data, offset + 48)
                initialized_size = _u64(record_data, offset + 56)
                summary.content_offset = runlist_offset
                summary.content_size = content_size
        else:
            if length < 24:
                record.warnings.append(f"resident attribute at offset {offset} is too short")
            else:
                content_size = _u32(record_data, offset + 16)
                relative_content_offset = _u16(record_data, offset + 20)
                content_offset = offset + relative_content_offset
                summary.content_offset = content_offset
                summary.content_size = content_size
                if content_offset + content_size > offset + length:
                    record.warnings.append(f"resident attribute at offset {offset} content extends beyond attribute")
                    content = record_data[content_offset : offset + length]
                else:
                    content = record_data[content_offset : content_offset + content_size]

        record.attributes.append(summary)

        if type_code == ATTR_STANDARD_INFORMATION and content:
            parsed = _parse_standard_information(content, offset, attribute_id, record.warnings)
            if parsed:
                record.standard_information.append(parsed)
        elif type_code == ATTR_FILE_NAME and content:
            parsed = _parse_file_name(content, offset, attribute_id, record.warnings)
            if parsed:
                record.file_names.append(parsed)
        elif type_code == ATTR_DATA:
            data_size = content_size
            record.data_attributes.append(
                DataAttribute(
                    attribute_offset=offset,
                    attribute_id=attribute_id,
                    name=name,
                    resident=not nonresident,
                    data_size=data_size,
                    allocated_size=allocated_size,
                    initialized_size=initialized_size,
                    is_ads=bool(name),
                )
            )

        offset += _align8(length)

    if offset < limit:
        record.warnings.append("attribute list ended without end marker")


def _parse_standard_information(
    content: bytes, attribute_offset: int, attribute_id: int, warnings: list[str]
) -> StandardInformation | None:
    if len(content) < 32:
        warnings.append("$STANDARD_INFORMATION content is too short")
        return None
    file_attributes = _u32(content, 32) if len(content) >= 36 else None
    return StandardInformation(
        attribute_offset=attribute_offset,
        attribute_id=attribute_id,
        timestamps=TimestampSet(
            created=filetime_to_iso(_u64(content, 0)),
            modified=filetime_to_iso(_u64(content, 8)),
            mft_modified=filetime_to_iso(_u64(content, 16)),
            accessed=filetime_to_iso(_u64(content, 24)),
        ),
        file_attributes=file_attributes,
    )


def _parse_file_name(
    content: bytes, attribute_offset: int, attribute_id: int, warnings: list[str]
) -> FileNameAttribute | None:
    if len(content) < 66:
        warnings.append("$FILE_NAME content is too short")
        return None

    name_length = content[64]
    namespace = content[65]
    name_byte_length = name_length * 2
    if 66 + name_byte_length > len(content):
        warnings.append("$FILE_NAME name extends beyond content")
        name_byte_length = max(0, len(content) - 66)

    return FileNameAttribute(
        attribute_offset=attribute_offset,
        attribute_id=attribute_id,
        parent_reference=parse_file_reference(_u64(content, 0)),
        timestamps=TimestampSet(
            created=filetime_to_iso(_u64(content, 8)),
            modified=filetime_to_iso(_u64(content, 16)),
            mft_modified=filetime_to_iso(_u64(content, 24)),
            accessed=filetime_to_iso(_u64(content, 32)),
        ),
        allocated_size=_u64(content, 40),
        real_size=_u64(content, 48),
        file_attributes=_u32(content, 56),
        namespace=namespace,
        namespace_name=FILE_NAME_NAMESPACES.get(namespace, f"UNKNOWN_{namespace}"),
        name=_decode_utf16(content, 66, name_byte_length),
    )


def _timeline_event(
    result: MftParseResult,
    record: MftRecord,
    timestamp: str | None,
    action: str,
    attribute_offset: int | None,
    attribute_type: str,
    confidence_label: str,
    attributes: dict[str, Any],
    *,
    path: str | None = None,
) -> dict[str, Any]:
    confidence = {"high": 0.94, "medium": 0.82, "low": 0.64}[confidence_label]
    return {
        "timestamp": timestamp,
        "source_artifact": "NTFS:$MFT",
        "record_id": record.record_id,
        "path": path or record.path,
        "action": action,
        "confidence": confidence,
        "provenance": {
            "parser": "dfatool.mft",
            "artifact_hash": result.artifact_hash,
            "artifact_path": result.artifact_path,
            "mft_entry": record.entry,
            "sequence_number": record.sequence_number,
            "record_offset": record.record_offset,
            "attribute_offset": attribute_offset,
            "attribute_type": attribute_type,
            "record_size": result.record_size,
        },
        "attributes": attributes,
    }


def _metadata_anchor(record: MftRecord) -> dict[str, Any]:
    if record.standard_information:
        si = record.standard_information[0]
        timestamp = si.timestamps.mft_modified or si.timestamps.modified or si.timestamps.created
        return {
            "timestamp": timestamp,
            "attribute_offset": si.attribute_offset,
            "attribute_type": "$STANDARD_INFORMATION",
        }
    if record.file_names:
        fn = _preferred_file_name(record) or record.file_names[0]
        timestamp = fn.timestamps.mft_modified or fn.timestamps.modified or fn.timestamps.created
        return {
            "timestamp": timestamp,
            "attribute_offset": fn.attribute_offset,
            "attribute_type": "$FILE_NAME",
        }
    return {"timestamp": None, "attribute_offset": None, "attribute_type": "FILE record"}


def _deleted_anchor(record: MftRecord) -> dict[str, Any]:
    if record.file_names:
        fn = _preferred_file_name(record) or record.file_names[0]
        timestamp = fn.timestamps.mft_modified or fn.timestamps.modified or fn.timestamps.created
        return {
            "timestamp": timestamp,
            "attribute_offset": fn.attribute_offset,
            "attribute_type": "$FILE_NAME",
        }
    return _metadata_anchor(record)


def _timeline_file_names(record: MftRecord) -> Iterable[FileNameAttribute]:
    non_dos = [file_name for file_name in record.file_names if file_name.namespace != 2]
    return non_dos or record.file_names


def _preferred_file_name(record: MftRecord) -> FileNameAttribute | None:
    if not record.file_names:
        return None
    order = {1: 0, 3: 1, 0: 2, 2: 3}
    return sorted(record.file_names, key=lambda item: (order.get(item.namespace, 9), item.name))[0]


def _decode_utf16(data: bytes, offset: int, length: int) -> str:
    if length <= 0:
        return ""
    raw = data[offset : offset + length]
    return raw.decode("utf-16le", errors="replace").rstrip("\x00")


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]
