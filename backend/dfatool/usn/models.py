from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from dfatool.usn.constants import FILE_ATTRIBUTE_DIRECTORY


@dataclass(frozen=True, slots=True)
class UsnFileReference:
    entry: int | None
    sequence: int | None
    raw: int

    def to_dict(self) -> dict[str, int | None]:
        return {"entry": self.entry, "sequence": self.sequence, "raw": self.raw}


@dataclass(frozen=True, slots=True)
class UsnRecord:
    record_length: int
    major_version: int
    minor_version: int
    file_reference_number: int
    parent_file_reference_number: int
    file_reference: UsnFileReference
    parent_file_reference: UsnFileReference
    usn: int
    timestamp: str | None
    raw_reason: int
    reason_flags: list[str]
    source_info: int
    security_id: int
    file_attributes: int
    file_name_length: int
    file_name_offset: int
    file_name: str
    record_offset: int
    warnings: list[str] = field(default_factory=list)

    @property
    def record_id(self) -> str:
        return str(self.usn)

    @property
    def is_directory(self) -> bool:
        return bool(self.file_attributes & FILE_ATTRIBUTE_DIRECTORY)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_length": self.record_length,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "file_reference_number": self.file_reference_number,
            "parent_file_reference_number": self.parent_file_reference_number,
            "file_reference": self.file_reference.to_dict(),
            "parent_file_reference": self.parent_file_reference.to_dict(),
            "usn": self.usn,
            "timestamp": self.timestamp,
            "raw_reason": self.raw_reason,
            "reason_flags": list(self.reason_flags),
            "source_info": self.source_info,
            "security_id": self.security_id,
            "file_attributes": self.file_attributes,
            "file_name_length": self.file_name_length,
            "file_name_offset": self.file_name_offset,
            "file_name": self.file_name,
            "record_offset": self.record_offset,
            "record_id": self.record_id,
            "is_directory": self.is_directory,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class UsnParseResult:
    artifact_path: str
    artifact_hash: str
    records: list[UsnRecord]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_path": self.artifact_path,
            "artifact_hash": self.artifact_hash,
            "record_count": len(self.records),
            "warnings": list(self.warnings),
            "records": [record.to_dict() for record in self.records],
        }
