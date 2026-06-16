from __future__ import annotations

from typing import Any

from dfatool.usn.constants import (
    CONTENT_REASON_FLAGS,
    DIRECT_ACTIONS,
    PARSER_NAME,
    PARSER_VERSION,
    SOURCE_ARTIFACT,
    TIMESTAMP_SOURCE,
)
from dfatool.usn.models import UsnParseResult, UsnRecord


def build_timeline_events(result: UsnParseResult, *, max_events: int = 1_000_000) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for record in result.records:
        for action in _actions_for_record(record):
            _append_limited_event(events, _timeline_event(result, record, action), result, max_events)
            if len(events) >= max_events:
                return events
    return events


def _actions_for_record(record: UsnRecord) -> list[str]:
    actions: list[str] = []
    if any(flag in CONTENT_REASON_FLAGS for flag in record.reason_flags):
        actions.append("file_content_modified")
    for reason_name, action in DIRECT_ACTIONS.items():
        if reason_name in record.reason_flags:
            actions.append(action)
    if not actions and record.reason_flags == ["CLOSE"]:
        actions.append("file_closed")
    return actions


def _timeline_event(result: UsnParseResult, record: UsnRecord, action: str) -> dict[str, Any]:
    attributes = _base_attributes(record)
    confidence = 0.55 if action == "file_closed" else 0.9
    return {
        "timestamp": record.timestamp,
        "source_artifact": SOURCE_ARTIFACT,
        "record_id": record.record_id,
        "path": record.file_name or "<unknown>",
        "action": action,
        "confidence": confidence,
        "provenance": _provenance(result, record, attributes),
        "attributes": attributes,
    }


def _base_attributes(record: UsnRecord) -> dict[str, Any]:
    path_warnings = [
        "USN record stores file name and parent reference only; full path reconstruction requires MFT linkage."
    ]
    if not record.file_name:
        path_warnings.append("USN record did not include a usable file name.")
    return {
        "timestamp_source": TIMESTAMP_SOURCE,
        "file_name": record.file_name,
        "file_reference_number": record.file_reference_number,
        "parent_file_reference_number": record.parent_file_reference_number,
        "file_reference": record.file_reference.to_dict(),
        "parent_file_reference": record.parent_file_reference.to_dict(),
        "raw_reason": record.raw_reason,
        "reason_flags": list(record.reason_flags),
        "source_info": record.source_info,
        "security_id": record.security_id,
        "file_attributes": record.file_attributes,
        "is_directory": record.is_directory,
        "directory": record.is_directory,
        "path_confidence": "low",
        "path_warnings": path_warnings,
        "parser_warnings": list(record.warnings),
    }


def _provenance(result: UsnParseResult, record: UsnRecord, attributes: dict[str, Any]) -> dict[str, Any]:
    canonical = {
        "parser_name": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "artifact_sha256": result.artifact_hash,
        "artifact_path": result.artifact_path,
        "record_offset": record.record_offset,
        "record_length": record.record_length,
        "usn": record.usn,
        "file_reference_number": record.file_reference_number,
        "parent_file_reference_number": record.parent_file_reference_number,
        "raw_reason": record.raw_reason,
        "reason_flags": list(record.reason_flags),
        "file_attributes": record.file_attributes,
        "file_name": record.file_name,
        "timestamp_source": TIMESTAMP_SOURCE,
        "parser_warnings": list(record.warnings),
    }
    return {**canonical, **_legacy_aliases(canonical), **attributes}


def _legacy_aliases(canonical: dict[str, Any]) -> dict[str, Any]:
    return {
        "parser": canonical["parser_name"],
        "artifact_hash": canonical["artifact_sha256"],
    }


def _append_limited_event(
    events: list[dict[str, Any]],
    event: dict[str, Any],
    result: UsnParseResult,
    max_events: int,
) -> None:
    if len(events) < max_events:
        events.append(event)
        if len(events) == max_events:
            _record_event_limit(result, max_events)
        return
    _record_event_limit(result, max_events)


def _record_event_limit(result: UsnParseResult, max_events: int) -> None:
    if not any("timeline event limit reached" in warning for warning in result.warnings):
        result.warnings.append(f"timeline event limit reached at {max_events} events")
