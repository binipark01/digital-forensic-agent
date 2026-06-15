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
    parser_mode: Literal["auto", "sidecar", "sleuthkit"] = "auto"


class AnalysisRunOut(BaseModel):
    id: str
    case_id: str
    image_id: str
    status: str
    parser_mode: str
    started_at: str
    completed_at: str | None
    command_line: str
    tool_versions: dict[str, Any]
    warning: str
    event_count: int


class TimelineEventOut(BaseModel):
    id: str
    case_id: str
    image_id: str
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

