from __future__ import annotations

from typing import Any

from dfatool.mft.constants import PARSER_NAME, PARSER_VERSION
from dfatool.mft.models import MftParseResult, MftRecord


def mft_provenance(
    result: MftParseResult,
    record: MftRecord,
    *,
    attribute_offset: int | None,
    attribute_type: str,
    attributes: dict[str, Any],
) -> dict[str, Any]:
    canonical = {
        "parser_name": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "artifact_sha256": result.artifact_hash,
        "artifact_path": result.artifact_path,
        "mft_entry_number": record.entry,
        "sequence_number": record.sequence_number,
        "record_offset": record.record_offset,
        "attribute_offset": attribute_offset,
        "attribute_type": attribute_type,
        "timestamp_source": attributes.get("timestamp_source"),
        "timestamp_field": attributes.get("timestamp_field"),
        "file_name": attributes.get("file_name"),
        "parent_reference": attributes.get("parent_reference"),
        "is_deleted": record.is_deleted,
        "is_directory": record.is_directory,
        "parser_warnings": list(record.warnings),
        "record_size": result.record_size,
    }
    return {**canonical, **_legacy_aliases(canonical)}


def _legacy_aliases(canonical: dict[str, Any]) -> dict[str, Any]:
    return {
        "parser": canonical["parser_name"],
        "artifact_hash": canonical["artifact_sha256"],
        "mft_entry": canonical["mft_entry_number"],
    }
