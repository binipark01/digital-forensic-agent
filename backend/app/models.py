from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class EvidenceSourceRegistration:
    case_id: str
    name: str
    source_type: str
    root_path: Path


@dataclass(frozen=True, slots=True)
class CollectionTargetSpec:
    artifact_type: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class ClassifiedTarget:
    id: str
    artifact_type: str
    relative_path: str
    classification: str
    resolved_path: str | None
    parser_hint: dict[str, Any]
    reason: str


@dataclass(frozen=True, slots=True)
class FileHashes:
    md5: str
    sha1: str
    sha256: str


@dataclass(frozen=True, slots=True)
class AnalysisWarning:
    code: str
    artifact_id: str
    artifact_type: str
    message: str
