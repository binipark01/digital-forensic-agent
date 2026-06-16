from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class NormalizedEvent:
    timestamp: str | None
    source_artifact: str
    record_id: str
    path: str
    action: str
    confidence: float
    provenance: dict[str, Any]
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    events: list[NormalizedEvent]
    parser_name: str
    warning: str = ""
    parser_version: str = ""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def epoch_to_iso(value: str) -> str | None:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return datetime.fromtimestamp(seconds, UTC).isoformat()
