from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    examiner: str = Field(default="", max_length=160)
    description: str = Field(default="", max_length=2000)


class CaseOut(BaseModel):
    id: str
    name: str
    examiner: str
    description: str
    created_at: str
    image_count: int = 0
    event_count: int = 0


class ImageRegister(BaseModel):
    path: str = Field(min_length=1)


class ImageOut(BaseModel):
    id: str
    case_id: str
    path: str
    format: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    registered_at: str
    parser_hints: dict[str, Any]


class AnalysisRequest(BaseModel):
    image_id: str | None = None
    artifact_ids: list[str] = Field(default_factory=list)
    parser_mode: Literal["auto", "dfatool_mft", "dfatool_usn", "sidecar", "sleuthkit"] = "auto"


class AnalysisRunOut(BaseModel):
    id: str
    case_id: str
    image_id: str | None
    artifact_id: str | None = None
    status: str
    parser_mode: str
    started_at: str
    completed_at: str | None
    command_line: str
    tool_versions: dict[str, Any]
    warning: str
    warnings: list[dict[str, Any]] = Field(default_factory=list)
    event_count: int


class TimelineEventOut(BaseModel):
    id: str
    case_id: str
    image_id: str | None
    artifact_id: str | None = None
    run_id: str
    timestamp: str | None
    source_artifact: str
    record_id: str
    path: str
    action: str
    confidence: float
    provenance: dict[str, Any]
    attributes: dict[str, Any]
    created_at: str


class TimelineResponse(BaseModel):
    events: list[TimelineEventOut]
    total: int
    limit: int
    offset: int


class ReportRequest(BaseModel):
    format: Literal["markdown", "json", "csv"] = "markdown"


class ReportOut(BaseModel):
    id: str
    case_id: str
    format: str
    path: str
    generated_at: str
    event_count: int
    content_preview: str


class Recommendation(BaseModel):
    title: str
    rationale: str
    evidence_event_ids: list[str]
    next_steps: list[str]


class RecommendationsOut(BaseModel):
    recommendations: list[Recommendation]
    generated_from_event_count: int


class EvidenceSourceCreate(BaseModel):
    name: str | None = Field(default=None, max_length=160)
    label: str | None = Field(default=None, max_length=160)
    source_type: Literal[
        "mounted_windows_directory",
        "mounted_windows_volume",
        "mounted_directory",
        "mounted_volume",
    ]
    root_path: str | None = Field(default=None, min_length=1)
    path: str | None = Field(default=None, min_length=1)


class EvidenceSourceOut(BaseModel):
    id: str
    case_id: str
    name: str
    source_type: str
    root_path: str
    registered_at: str
    metadata: dict[str, Any]


class CollectionTargetCreate(BaseModel):
    artifact_type: str = Field(min_length=1)
    relative_path: str = Field(min_length=1)


class CollectionPlanCreate(BaseModel):
    name: str = Field(default="Windows triage collection plan", max_length=160)
    evidence_source_id: str | None = None
    targets: list[CollectionTargetCreate] | None = Field(default=None)


class CollectionTargetOut(BaseModel):
    id: str
    plan_id: str
    artifact_type: str
    relative_path: str
    resolved_path: str | None
    classification: str
    parser_hint: dict[str, Any]
    reason: str


class CollectionPlanOut(BaseModel):
    id: str
    case_id: str
    evidence_source_id: str
    name: str
    status: str
    created_at: str
    executed_at: str | None
    registered_artifact_count: int
    targets: list[CollectionTargetOut] = Field(default_factory=list)
    found_count: int = 0
    missing_count: int = 0


class EvidenceArtifactOut(BaseModel):
    id: str
    case_id: str
    evidence_source_id: str
    collection_plan_id: str
    collection_target_id: str
    artifact_type: str
    path: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    parser_hint: dict[str, Any]
    registered_at: str


class EvidenceArtifactsOut(BaseModel):
    artifacts: list[EvidenceArtifactOut]


class CollectionExecutionOut(BaseModel):
    plan_id: str
    status: str
    registered_artifact_count: int
    artifacts: list[EvidenceArtifactOut]
