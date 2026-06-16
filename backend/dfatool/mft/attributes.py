from __future__ import annotations

from dfatool.mft.binary import align8, decode_utf16, filetime_to_iso, parse_file_reference, u16, u32, u64
from dfatool.mft.constants import (
    ATTRIBUTE_END,
    ATTRIBUTE_NAMES,
    ATTR_DATA,
    ATTR_FILE_NAME,
    ATTR_STANDARD_INFORMATION,
    FILE_NAME_NAMESPACES,
)
from dfatool.mft.models import (
    AttributeSummary,
    DataAttribute,
    FileNameAttribute,
    MftRecord,
    StandardInformation,
    TimestampSet,
)


def parse_attributes(record_data: bytes, record: MftRecord) -> None:
    offset = record.first_attribute_offset
    limit = min(record.used_size if record.used_size > 0 else len(record_data), len(record_data))

    while offset + 4 <= limit:
        type_code = u32(record_data, offset)
        if type_code == ATTRIBUTE_END:
            return
        if offset + 16 > limit:
            record.warnings.append(f"attribute header at offset {offset} is truncated")
            return

        length = u32(record_data, offset + 4)
        if length < 16:
            record.warnings.append(f"attribute at offset {offset} has invalid length {length}")
            return
        if offset + length > len(record_data):
            record.warnings.append(f"attribute at offset {offset} extends beyond record")
            return

        content, summary, sizes = _attribute_content(record_data, offset, length, type_code, record)
        record.attributes.append(summary)
        _append_known_attribute(record, type_code, content, summary, sizes)
        offset += align8(length)

    if record_data[offset:limit].strip(b"\x00"):
        record.warnings.append("attribute list ended without end marker")


def _attribute_content(
    record_data: bytes,
    offset: int,
    length: int,
    type_code: int,
    record: MftRecord,
) -> tuple[bytes, AttributeSummary, dict[str, int | None]]:
    nonresident = bool(record_data[offset + 8])
    name_length = record_data[offset + 9]
    name_offset = u16(record_data, offset + 10)
    attribute_id = u16(record_data, offset + 14)
    name = decode_utf16(record_data, offset + name_offset, name_length * 2) if name_length else ""
    summary = AttributeSummary(
        type_code=type_code,
        type_name=ATTRIBUTE_NAMES.get(type_code, f"UNKNOWN_{type_code:#x}"),
        offset=offset,
        length=length,
        resident=not nonresident,
        name=name,
        attribute_id=attribute_id,
    )
    sizes: dict[str, int | None] = {
        "content_size": None,
        "allocated_size": None,
        "initialized_size": None,
    }
    if nonresident:
        _populate_nonresident_summary(record_data, offset, length, summary, sizes, record)
        return b"", summary, sizes
    return _resident_content(record_data, offset, length, summary, sizes, record), summary, sizes


def _populate_nonresident_summary(
    record_data: bytes,
    offset: int,
    length: int,
    summary: AttributeSummary,
    sizes: dict[str, int | None],
    record: MftRecord,
) -> None:
    if length < 64:
        record.warnings.append(f"nonresident attribute at offset {offset} is too short")
        return
    summary.content_offset = u16(record_data, offset + 32)
    sizes["allocated_size"] = u64(record_data, offset + 40)
    sizes["content_size"] = u64(record_data, offset + 48)
    sizes["initialized_size"] = u64(record_data, offset + 56)
    summary.content_size = sizes["content_size"]


def _resident_content(
    record_data: bytes,
    offset: int,
    length: int,
    summary: AttributeSummary,
    sizes: dict[str, int | None],
    record: MftRecord,
) -> bytes:
    if length < 24:
        record.warnings.append(f"resident attribute at offset {offset} is too short")
        return b""
    content_size = u32(record_data, offset + 16)
    content_offset = offset + u16(record_data, offset + 20)
    sizes["content_size"] = content_size
    summary.content_offset = content_offset
    summary.content_size = content_size
    if content_offset + content_size > offset + length:
        record.warnings.append(f"resident attribute at offset {offset} content extends beyond attribute")
        return record_data[content_offset : offset + length]
    return record_data[content_offset : content_offset + content_size]


def _append_known_attribute(
    record: MftRecord,
    type_code: int,
    content: bytes,
    summary: AttributeSummary,
    sizes: dict[str, int | None],
) -> None:
    if type_code == ATTR_STANDARD_INFORMATION and content:
        parsed_si = _parse_standard_information(content, summary.offset, summary.attribute_id, record.warnings)
        if parsed_si:
            record.standard_information.append(parsed_si)
    elif type_code == ATTR_FILE_NAME and content:
        parsed_fn = _parse_file_name(content, summary.offset, summary.attribute_id, record.warnings)
        if parsed_fn:
            record.file_names.append(parsed_fn)
    elif type_code == ATTR_DATA:
        record.data_attributes.append(
            DataAttribute(
                attribute_offset=summary.offset,
                attribute_id=summary.attribute_id,
                name=summary.name,
                resident=summary.resident,
                data_size=sizes["content_size"],
                allocated_size=sizes["allocated_size"],
                initialized_size=sizes["initialized_size"],
                is_ads=bool(summary.name),
            )
        )


def _parse_standard_information(
    content: bytes, attribute_offset: int, attribute_id: int, warnings: list[str]
) -> StandardInformation | None:
    if len(content) < 32:
        warnings.append("$STANDARD_INFORMATION content is too short")
        return None
    return StandardInformation(
        attribute_offset=attribute_offset,
        attribute_id=attribute_id,
        timestamps=_timestamps_from(content, 0),
        file_attributes=u32(content, 32) if len(content) >= 36 else None,
    )


def _parse_file_name(
    content: bytes, attribute_offset: int, attribute_id: int, warnings: list[str]
) -> FileNameAttribute | None:
    if len(content) < 66:
        warnings.append("$FILE_NAME content is too short")
        return None
    name_byte_length = content[64] * 2
    if 66 + name_byte_length > len(content):
        warnings.append("$FILE_NAME name extends beyond content")
        name_byte_length = max(0, len(content) - 66)
    namespace = content[65]
    return FileNameAttribute(
        attribute_offset=attribute_offset,
        attribute_id=attribute_id,
        parent_reference=parse_file_reference(u64(content, 0)),
        timestamps=_timestamps_from(content, 8),
        allocated_size=u64(content, 40),
        real_size=u64(content, 48),
        file_attributes=u32(content, 56),
        namespace=namespace,
        namespace_name=FILE_NAME_NAMESPACES.get(namespace, f"UNKNOWN_{namespace}"),
        name=decode_utf16(content, 66, name_byte_length),
    )


def _timestamps_from(content: bytes, offset: int) -> TimestampSet:
    return TimestampSet(
        created=filetime_to_iso(u64(content, offset)),
        modified=filetime_to_iso(u64(content, offset + 8)),
        mft_modified=filetime_to_iso(u64(content, offset + 16)),
        accessed=filetime_to_iso(u64(content, offset + 24)),
    )
