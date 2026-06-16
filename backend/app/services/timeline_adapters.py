from __future__ import annotations

import csv
import json
import struct
from pathlib import Path
from typing import Any

from app.services.analysis_types import AnalysisResult, NormalizedEvent
from dfatool.mft import build_timeline_events, parse_mft_file
from dfatool.mft.binary import MftParseError, sha256_file
from dfatool.mft.constants import PARSER_NAME as MFT_PARSER_NAME
from dfatool.mft.constants import PARSER_VERSION as MFT_PARSER_VERSION


class SidecarTimelineAdapter:
    name = "sidecar"

    def candidates(self, image_path: Path) -> list[Path]:
        return [
            Path(f"{image_path}.timeline.json"),
            Path(f"{image_path}.timeline.csv"),
            image_path.with_suffix(".timeline.json"),
            image_path.with_suffix(".timeline.csv"),
        ]

    def can_run(self, image_path: Path) -> bool:
        return any(candidate.exists() for candidate in self.candidates(image_path))

    def run(self, image_path: Path) -> AnalysisResult:
        for candidate in self.candidates(image_path):
            if candidate.exists() and candidate.suffix.lower() == ".json":
                return AnalysisResult(self._read_json(candidate), self.name)
            if candidate.exists() and candidate.suffix.lower() == ".csv":
                return AnalysisResult(self._read_csv(candidate), self.name)
        return AnalysisResult([], self.name, "No sidecar timeline found.")

    def _read_json(self, path: Path) -> list[NormalizedEvent]:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        rows = payload.get("events", payload if isinstance(payload, list) else [])
        return [self._event_from_mapping(row, str(path)) for row in rows]

    def _read_csv(self, path: Path) -> list[NormalizedEvent]:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return [self._event_from_mapping(row, str(path)) for row in csv.DictReader(handle)]

    def _event_from_mapping(self, row: dict[str, Any], source_path: str) -> NormalizedEvent:
        provenance = _json_mapping(row.get("provenance") or {})
        provenance.setdefault("parser", self.name)
        provenance.setdefault("source_path", source_path)
        return NormalizedEvent(
            timestamp=row.get("timestamp") or None,
            source_artifact=row.get("source_artifact") or "$MFT",
            record_id=str(row.get("record_id") or ""),
            path=row.get("path") or "",
            action=row.get("action") or "observed",
            confidence=float(row.get("confidence") or 0.75),
            provenance=provenance,
            attributes=_json_mapping(row.get("attributes") or {}),
        )


class DfatoolMftAdapter:
    name = MFT_PARSER_NAME
    version = MFT_PARSER_VERSION
    max_records = 250_000
    max_events = 1_000_000

    def can_run(self, image_path: Path) -> bool:
        if not image_path.exists() or image_path.stat().st_size < 1024:
            return False
        try:
            with image_path.open("rb") as handle:
                return handle.read(4) == b"FILE"
        except OSError:
            return False

    def run(self, image: dict[str, Any]) -> AnalysisResult:
        image_path = Path(image["path"])
        stored_sha256 = str(image.get("sha256") or "")
        try:
            current_sha256 = sha256_file(image_path)
            if stored_sha256 and current_sha256 != stored_sha256:
                return AnalysisResult([], self.name, _hash_mismatch_warning(), self.version)
            result = parse_mft_file(
                image_path,
                artifact_hash=stored_sha256 or current_sha256,
                max_records=self.max_records,
            )
        except (MftParseError, OSError, struct.error) as exc:
            return AnalysisResult([], self.name, _safe_parser_failure(exc), self.version)

        events = [
            self._event_from_mapping(row)
            for row in build_timeline_events(result, max_events=self.max_events)
        ]
        warnings = _parser_warnings(result)
        warning = "; ".join(warnings)
        if not events:
            warning = warning or "dfatool parsed the MFT but produced no timeline events."
        return AnalysisResult(events, self.name, warning, self.version)

    def _event_from_mapping(self, row: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            timestamp=row.get("timestamp"),
            source_artifact=row["source_artifact"],
            record_id=str(row["record_id"]),
            path=row.get("path") or "",
            action=row["action"],
            confidence=float(row["confidence"]),
            provenance=row.get("provenance") or {},
            attributes=row.get("attributes") or {},
        )


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            loaded = json.loads(value)
        except json.JSONDecodeError:
            return {"raw": value}
        return loaded if isinstance(loaded, dict) else {"raw": loaded}
    return {}


def _parser_warnings(result) -> list[str]:
    warnings = list(result.warnings)
    for record in result.records:
        warnings.extend(f"MFT entry {record.entry}: {warning}" for warning in record.warnings)
    return warnings


def _hash_mismatch_warning() -> str:
    return "Artifact bytes changed since registration; refusing to parse ntfs_mft with stale hash."


def _safe_parser_failure(exc: Exception) -> str:
    reason = type(exc).__name__
    return f"dfatool MFT parser failed before producing events ({reason})."
