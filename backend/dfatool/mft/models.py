from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class FileReference:
    entry: int
    sequence: int
    raw: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass
class TimestampSet:
    created: str | None = None
    modified: str | None = None
    mft_modified: str | None = None
    accessed: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


@dataclass
class StandardInformation:
    attribute_offset: int
    attribute_id: int
    timestamps: TimestampSet
    file_attributes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribute_offset": self.attribute_offset,
            "attribute_id": self.attribute_id,
            "timestamps": self.timestamps.to_dict(),
            "file_attributes": self.file_attributes,
        }


@dataclass
class FileNameAttribute:
    attribute_offset: int
    attribute_id: int
    parent_reference: FileReference
    timestamps: TimestampSet
    allocated_size: int
    real_size: int
    file_attributes: int
    namespace: int
    namespace_name: str
    name: str
    full_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribute_offset": self.attribute_offset,
            "attribute_id": self.attribute_id,
            "parent_reference": self.parent_reference.to_dict(),
            "timestamps": self.timestamps.to_dict(),
            "allocated_size": self.allocated_size,
            "real_size": self.real_size,
            "file_attributes": self.file_attributes,
            "namespace": self.namespace,
            "namespace_name": self.namespace_name,
            "name": self.name,
            "full_path": self.full_path,
        }


@dataclass
class DataAttribute:
    attribute_offset: int
    attribute_id: int
    name: str
    resident: bool
    data_size: int | None
    allocated_size: int | None
    initialized_size: int | None
    is_ads: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttributeSummary:
    type_code: int
    type_name: str
    offset: int
    length: int
    resident: bool
    name: str
    attribute_id: int
    content_offset: int | None = None
    content_size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MftRecord:
    entry: int
    sequence_number: int
    record_offset: int
    usa_offset: int
    usa_count: int
    lsn: int
    hard_link_count: int
    first_attribute_offset: int
    flags: int
    used_size: int
    allocated_size: int
    next_attribute_id: int
    active: bool
    is_directory: bool
    base_file_reference: FileReference | None
    standard_information: list[StandardInformation] = field(default_factory=list)
    file_names: list[FileNameAttribute] = field(default_factory=list)
    data_attributes: list[DataAttribute] = field(default_factory=list)
    attributes: list[AttributeSummary] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def record_id(self) -> str:
        return f"{self.entry}-{self.sequence_number}"

    @property
    def is_deleted(self) -> bool:
        return not self.active

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "sequence_number": self.sequence_number,
            "record_id": self.record_id,
            "record_offset": self.record_offset,
            "usa_offset": self.usa_offset,
            "usa_count": self.usa_count,
            "lsn": self.lsn,
            "hard_link_count": self.hard_link_count,
            "first_attribute_offset": self.first_attribute_offset,
            "flags": self.flags,
            "used_size": self.used_size,
            "allocated_size": self.allocated_size,
            "next_attribute_id": self.next_attribute_id,
            "active": self.active,
            "deleted": self.is_deleted,
            "is_directory": self.is_directory,
            "path": self.path,
            "base_file_reference": self.base_file_reference.to_dict()
            if self.base_file_reference
            else None,
            "standard_information": [item.to_dict() for item in self.standard_information],
            "file_names": [item.to_dict() for item in self.file_names],
            "data_attributes": [item.to_dict() for item in self.data_attributes],
            "attributes": [item.to_dict() for item in self.attributes],
            "warnings": list(self.warnings),
        }


@dataclass
class MftParseResult:
    artifact_path: str
    artifact_hash: str
    record_size: int
    sector_size: int
    records: list[MftRecord]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_path": self.artifact_path,
            "artifact_hash": self.artifact_hash,
            "record_size": self.record_size,
            "sector_size": self.sector_size,
            "record_count": len(self.records),
            "warnings": list(self.warnings),
            "records": [record.to_dict() for record in self.records],
        }
