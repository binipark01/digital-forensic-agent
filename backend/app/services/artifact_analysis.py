from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.database import Database, dumps, loads
from app.models import AnalysisWarning
from app.services.analysis_types import AnalysisResult, NormalizedEvent, utc_now
from app.services.forensics import parser_capabilities
from app.services.timeline_adapters import DfatoolMftAdapter, SidecarTimelineAdapter
from app.storage import CollectionStorage, warning_to_dict


@dataclass(frozen=True, slots=True)
class ArtifactEventBatch:
    artifact_id: str
    events: list[NormalizedEvent]


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    artifact_type: str
    parser_name: str
    priority: int


REGISTRY = (
    RegistryEntry("sidecar_timeline", "sidecar", 10),
    RegistryEntry("ntfs_mft", "dfatool_mft", 20),
    RegistryEntry("NTFS:$MFT", "dfatool_mft", 20),
)


class ArtifactAnalysisService:
    def __init__(self, db: Database):
        self.db = db
        self.storage = CollectionStorage(db)
        self.sidecar = SidecarTimelineAdapter()
        self.mft = DfatoolMftAdapter()

    def analyze(self, case_id: str, artifact_ids: list[str], parser_mode: str) -> dict[str, Any]:
        artifacts = self.storage.fetch_artifacts(case_id, artifact_ids)
        if len(artifacts) != len(artifact_ids):
            raise LookupError("evidence artifact not found")

        run_id = str(uuid.uuid4())
        started_at = utc_now()
        tool_versions = parser_capabilities()
        self.db.execute(
            """
            INSERT INTO analysis_runs (
                id, case_id, image_id, artifact_id, status, parser_mode, started_at,
                command_line, tool_versions, warnings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                case_id,
                None,
                artifacts[0]["id"] if len(artifacts) == 1 else None,
                "running",
                parser_mode,
                started_at,
                f"analyze --case {case_id} --artifacts {','.join(artifact_ids)} --parser-mode {parser_mode}",
                dumps(tool_versions),
                dumps([]),
            ),
        )

        batches: list[ArtifactEventBatch] = []
        warnings: list[AnalysisWarning] = []
        selected_parsers: list[str] = []
        parser_runs: list[dict[str, Any]] = []
        for artifact in artifacts:
            result = self._analyze_artifact(artifact, parser_mode)
            selected_parsers.append(result.parser_name)
            parser_runs.append(_parser_run(artifact, result))
            if result.warning:
                warnings.append(
                    AnalysisWarning(
                        code="parser_not_implemented"
                        if result.parser_name == "none"
                        else "parser_warning",
                        artifact_id=str(artifact["id"]),
                        artifact_type=str(artifact["artifact_type"]),
                        message=result.warning,
                    )
                )
            if result.events:
                batches.append(
                    ArtifactEventBatch(
                        artifact_id=str(artifact["id"]),
                        events=[
                            _with_artifact_provenance(event, artifact)
                            for event in result.events
                        ],
                    )
                )

        event_count = self._persist_events(case_id, run_id, batches)
        warning_rows = [warning_to_dict(warning) for warning in warnings]
        completed_at = utc_now()
        self.db.execute(
            """
            UPDATE analysis_runs
            SET status = ?, completed_at = ?, warning = ?, warnings = ?, event_count = ?, tool_versions = ?
            WHERE id = ?
            """,
            (
                "completed_with_warnings" if warnings else "completed",
                completed_at,
                "; ".join(warning.message for warning in warnings),
                dumps(warning_rows),
                event_count,
                dumps(
                    {
                        **tool_versions,
                        "selected_parsers": selected_parsers,
                        "parser_runs": parser_runs,
                    }
                ),
                run_id,
            ),
        )
        row = self.db.fetchone("SELECT * FROM analysis_runs WHERE id = ?", (run_id,))
        if row is None:
            raise LookupError("analysis run not found")
        return _normalize_run(row)

    def _analyze_artifact(self, artifact: dict[str, Any], parser_mode: str) -> AnalysisResult:
        artifact_type = str(artifact["artifact_type"])
        entries = [
            entry
            for entry in REGISTRY
            if entry.artifact_type == artifact_type
            and (parser_mode == "auto" or parser_mode == entry.parser_name)
        ]
        if not entries:
            return AnalysisResult(
                [],
                "none",
                f"No parser is implemented for artifact type {artifact_type}.",
            )
        entry = sorted(entries, key=lambda item: item.priority)[0]
        if entry.parser_name == "sidecar":
            return self._read_sidecar(Path(str(artifact["path"])))
        if entry.parser_name == "dfatool_mft":
            artifact_path = Path(str(artifact["path"]))
            if not self.mft.can_run(artifact_path):
                return AnalysisResult([], "dfatool.mft", "dfatool MFT parser cannot run for this artifact.")
            return self.mft.run(artifact)
        return AnalysisResult([], "none", f"No parser is implemented for artifact type {artifact_type}.")

    def _read_sidecar(self, path: Path) -> AnalysisResult:
        if path.suffix.lower() == ".json":
            return AnalysisResult(self.sidecar._read_json(path), self.sidecar.name)
        if path.suffix.lower() == ".csv":
            return AnalysisResult(self.sidecar._read_csv(path), self.sidecar.name)
        return AnalysisResult([], self.sidecar.name, "Sidecar timeline must be a JSON or CSV file.")

    def _persist_events(self, case_id: str, run_id: str, batches: list[ArtifactEventBatch]) -> int:
        created_at = utc_now()
        rows = []
        for batch in batches:
            for event in batch.events:
                rows.append(
                    (
                        str(uuid.uuid4()),
                        case_id,
                        None,
                        batch.artifact_id,
                        run_id,
                        event.timestamp,
                        event.source_artifact,
                        event.record_id,
                        event.path,
                        event.action,
                        max(0.0, min(1.0, event.confidence)),
                        dumps(event.provenance),
                        dumps(event.attributes),
                        created_at,
                    )
                )
        self.db.execute("DELETE FROM timeline_events WHERE run_id = ?", (run_id,))
        self.db.executemany(
            """
            INSERT INTO timeline_events (
                id, case_id, image_id, artifact_id, run_id, timestamp, source_artifact,
                record_id, path, action, confidence, provenance, attributes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        return len(rows)


def _with_artifact_provenance(event: NormalizedEvent, artifact: dict[str, Any]) -> NormalizedEvent:
    provenance = dict(event.provenance)
    provenance["artifact_id"] = artifact["id"]
    provenance["source_path"] = str(Path(str(artifact["path"])).resolve())
    return NormalizedEvent(
        timestamp=event.timestamp,
        source_artifact=event.source_artifact,
        record_id=event.record_id,
        path=event.path,
        action=event.action,
        confidence=event.confidence,
        provenance=provenance,
        attributes=dict(event.attributes),
    )


def _parser_run(artifact: dict[str, Any], result: AnalysisResult) -> dict[str, Any]:
    status = "skipped" if result.parser_name == "none" else "completed"
    if result.warning and status != "skipped":
        status = "completed_with_warnings"
    return {
        "artifact_id": artifact["id"],
        "artifact_type": artifact["artifact_type"],
        "parser_name": result.parser_name,
        "parser_version": result.parser_version,
        "status": status,
        "events_created": len(result.events),
        "warnings": [result.warning] if result.warning else [],
    }


def _normalize_run(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["tool_versions"] = loads(str(normalized.get("tool_versions") or ""), {})
    normalized["warnings"] = loads(str(normalized.get("warnings") or ""), [])
    return normalized
