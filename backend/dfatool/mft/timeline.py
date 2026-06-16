from __future__ import annotations

from typing import Any

from dfatool.mft.constants import SOURCE_ARTIFACTS, TIMESTAMP_ACTIONS
from dfatool.mft.limits import append_limited_event
from dfatool.mft.models import FileNameAttribute, MftParseResult, MftRecord
from dfatool.mft.paths import file_name_aliases, path_assessment, preferred_file_name, timeline_file_names
from dfatool.mft.provenance import mft_provenance


def build_timeline_events(result: MftParseResult, *, max_events: int = 1_000_000) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in result.records:
        for standard_information in record.standard_information:
            for field_name, timestamp in standard_information.timestamps.to_dict().items():
                if timestamp:
                    append_limited_event(
                        events,
                        _timestamp_event(
                            result,
                            record,
                            timestamp,
                            field_name,
                            standard_information.attribute_offset,
                            "$STANDARD_INFORMATION",
                            {
                                "timestamp_source": "$STANDARD_INFORMATION",
                                "timestamp_field": field_name,
                                "file_attributes": standard_information.file_attributes,
                            },
                        ),
                        result,
                        max_events,
                    )
                    if len(events) >= max_events:
                        return events

        for file_name in timeline_file_names(record):
            for field_name, timestamp in file_name.timestamps.to_dict().items():
                if timestamp:
                    append_limited_event(
                        events,
                        _timestamp_event(
                            result,
                            record,
                            timestamp,
                            field_name,
                            file_name.attribute_offset,
                            "$FILE_NAME",
                            {
                                "timestamp_source": "$FILE_NAME",
                                "timestamp_field": field_name,
                                "file_name_namespace": file_name.namespace_name,
                                "allocated_size": file_name.allocated_size,
                                "real_size": file_name.real_size,
                            },
                            file_name=file_name,
                        ),
                        result,
                        max_events,
                    )
                    if len(events) >= max_events:
                        return events

        if record.is_deleted:
            append_limited_event(events, _deleted_event(result, record), result, max_events)
            if len(events) >= max_events:
                return events
        for data_attr in record.data_attributes:
            if data_attr.is_ads:
                append_limited_event(
                    events,
                    _metadata_event(
                        result,
                        record,
                        _metadata_anchor(record),
                        "ads_detected",
                        data_attr.attribute_offset,
                        "$DATA",
                        {
                            "stream_name": data_attr.name,
                            "timestamp_source": _metadata_anchor(record)["attribute_type"],
                        },
                    ),
                    result,
                    max_events,
                )
                if len(events) >= max_events:
                    return events
    return events


def _timestamp_event(
    result: MftParseResult,
    record: MftRecord,
    timestamp: str,
    field_name: str,
    attribute_offset: int | None,
    attribute_type: str,
    extra_attributes: dict[str, Any],
    *,
    file_name: FileNameAttribute | None = None,
) -> dict[str, Any]:
    return _timeline_event(
        result,
        record,
        timestamp,
        TIMESTAMP_ACTIONS[field_name],
        attribute_offset,
        attribute_type,
        "high",
        {**_base_attributes(record, file_name), **extra_attributes},
        path=(file_name.full_path if file_name else None) or record.path,
    )


def _deleted_event(result: MftParseResult, record: MftRecord) -> dict[str, Any]:
    anchor = _deleted_anchor(record)
    return _metadata_event(
        result,
        record,
        anchor,
        "deleted_record_seen",
        anchor["attribute_offset"],
        anchor["attribute_type"],
        {
            "timestamp_source": anchor["attribute_type"],
            "reason": "MFT record in-use flag is unset",
        },
    )


def _metadata_event(
    result: MftParseResult,
    record: MftRecord,
    anchor: dict[str, Any],
    action: str,
    attribute_offset: int | None,
    attribute_type: str,
    extra_attributes: dict[str, Any],
) -> dict[str, Any]:
    return _timeline_event(
        result,
        record,
        anchor["timestamp"],
        action,
        attribute_offset,
        attribute_type,
        "medium",
        {**_base_attributes(record), **extra_attributes},
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
    source_artifact = SOURCE_ARTIFACTS.get(attribute_type, "NTFS:$MFT")
    provenance = mft_provenance(
        result,
        record,
        attribute_offset=attribute_offset,
        attribute_type=attribute_type,
        attributes=attributes,
    )
    return {
        "timestamp": timestamp,
        "source_artifact": source_artifact,
        "record_id": record.record_id,
        "path": path or record.path,
        "action": action,
        "confidence": confidence,
        "provenance": provenance,
        "attributes": attributes,
    }


def _base_attributes(
    record: MftRecord, file_name: FileNameAttribute | None = None
) -> dict[str, Any]:
    selected = file_name or preferred_file_name(record)
    confidence, path_warnings = path_assessment(
        record,
        selected.full_path if selected and selected.full_path else record.path,
    )
    parent_reference = selected.parent_reference.to_dict() if selected else None
    return {
        "active": record.active,
        "is_deleted": record.is_deleted,
        "deleted": record.is_deleted,
        "is_directory": record.is_directory,
        "directory": record.is_directory,
        "file_name": selected.name if selected else "",
        "file_name_namespace": selected.namespace_name if selected else "",
        "file_name_aliases": file_name_aliases(record, selected),
        "parent_reference": parent_reference,
        "path_confidence": confidence,
        "path_warnings": path_warnings,
        "data_streams": [stream.to_dict() for stream in record.data_attributes],
        "parser_warnings": list(record.warnings),
    }


def _metadata_anchor(record: MftRecord) -> dict[str, Any]:
    if record.standard_information:
        si = record.standard_information[0]
        return {
            "timestamp": si.timestamps.mft_modified or si.timestamps.modified or si.timestamps.created,
            "attribute_offset": si.attribute_offset,
            "attribute_type": "$STANDARD_INFORMATION",
        }
    if record.file_names:
        fn = preferred_file_name(record) or record.file_names[0]
        return {
            "timestamp": fn.timestamps.mft_modified or fn.timestamps.modified or fn.timestamps.created,
            "attribute_offset": fn.attribute_offset,
            "attribute_type": "$FILE_NAME",
        }
    return {"timestamp": None, "attribute_offset": None, "attribute_type": "FILE record"}


def _deleted_anchor(record: MftRecord) -> dict[str, Any]:
    if record.file_names:
        fn = preferred_file_name(record) or record.file_names[0]
        return {
            "timestamp": fn.timestamps.mft_modified or fn.timestamps.modified or fn.timestamps.created,
            "attribute_offset": fn.attribute_offset,
            "attribute_type": "$FILE_NAME",
        }
    return _metadata_anchor(record)

