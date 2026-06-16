from __future__ import annotations

import uuid
from pathlib import Path, PureWindowsPath
from typing import Any

from app.database import Database, loads
from app.models import (
    ClassifiedTarget,
    CollectionTargetSpec,
    EvidenceSourceRegistration,
    FileHashes,
)
from app.services.collection_catalog import (
    ALLOWED_SOURCE_TYPES,
    DEFAULT_DISCOVERY_PATTERNS,
    PARSER_HINTS,
    UNSUPPORTED_PARSER_HINT,
)
from app.services.analyzer import utc_now
from app.services.forensics import hash_file
from app.storage import CollectionStorage

RequestedTarget = CollectionTargetSpec


class CollectionService:
    def __init__(self, storage: CollectionStorage | Database):
        self.storage = storage if isinstance(storage, CollectionStorage) else CollectionStorage(storage)

    def create_source(
        self,
        case_id: str,
        name: str,
        source_type: str,
        root_path: Path,
    ) -> dict[str, Any]:
        return self._normalize_source(
            self.register_source(
                EvidenceSourceRegistration(
                    case_id=case_id,
                    name=name,
                    source_type=source_type,
                    root_path=root_path,
                )
            )
        )

    def list_sources(self, case_id: str) -> list[dict[str, Any]]:
        return [self._normalize_source(row) for row in self.storage.list_sources(case_id)]

    def register_source(self, registration: EvidenceSourceRegistration) -> dict[str, object]:
        if registration.source_type not in ALLOWED_SOURCE_TYPES:
            raise ValueError("unsupported evidence source type")

        root_path = registration.root_path.expanduser().resolve()
        if not root_path.exists() or not root_path.is_dir():
            raise FileNotFoundError(str(root_path))

        return self.storage.insert_source(
            str(uuid.uuid4()),
            registration.case_id,
            registration.name,
            registration.source_type,
            str(root_path),
            utc_now(),
        )

    def create_plan(
        self,
        case_id: str,
        source_id: str,
        name: str,
        target_specs: list[CollectionTargetSpec] | None,
    ) -> dict[str, object]:
        source = self.storage.require_source(case_id, source_id)
        root_path = Path(str(source["root_path"]))
        requested_targets = target_specs or _discover_targets(root_path)
        targets = [
            self._classify_target(root_path, target_spec)
            for target_spec in requested_targets
        ]
        plan = self.storage.insert_plan(str(uuid.uuid4()), case_id, source_id, name, utc_now(), targets)
        return self._normalize_plan(plan)

    def list_targets(self, case_id: str, plan_id: str) -> list[dict[str, Any]]:
        self.storage.require_plan(case_id, plan_id)
        return [self._normalize_target(row) for row in self.storage.list_plan_targets(plan_id)]

    def list_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        return [self._normalize_artifact(row) for row in self.storage.list_artifacts(case_id)]

    def get_artifact(self, case_id: str, artifact_id: str) -> dict[str, Any]:
        artifacts = self.storage.fetch_artifacts(case_id, [artifact_id])
        if not artifacts:
            raise LookupError("evidence artifact not found")
        return self._normalize_artifact(artifacts[0])

    def execute_plan(self, case_id: str, plan_id: str) -> dict[str, object]:
        plan = self.storage.require_plan(case_id, plan_id)
        source_id = str(plan["evidence_source_id"])
        targets = self.storage.list_plan_targets(plan_id)
        registered_count = 0
        artifacts: list[dict[str, Any]] = []

        for target in targets:
            if target["classification"] != "found" or target["resolved_path"] is None:
                continue
            artifact_path = Path(str(target["resolved_path"]))
            hashes = hash_file(artifact_path)
            artifact = self.storage.insert_artifact(
                str(uuid.uuid4()),
                case_id,
                source_id,
                plan_id,
                str(target["id"]),
                str(target["artifact_type"]),
                str(artifact_path.resolve()),
                artifact_path.stat().st_size,
                FileHashes(
                    md5=hashes["md5"],
                    sha1=hashes["sha1"],
                    sha256=hashes["sha256"],
                ),
                loads(str(target["parser_hint"]), {}),
                utc_now(),
            )
            artifacts.append(self._normalize_artifact(artifact))
            registered_count += 1

        executed_at = utc_now()
        self.storage.mark_plan_executed(plan_id, executed_at, registered_count)
        return {
            "plan_id": plan_id,
            "status": "completed",
            "registered_artifact_count": registered_count,
            "artifacts": artifacts,
        }

    def _classify_target(self, root_path: Path, target_spec: CollectionTargetSpec) -> ClassifiedTarget:
        resolved_path = _resolve_relative_path(root_path, target_spec.relative_path)
        parser_hint = PARSER_HINTS.get(
            target_spec.artifact_type,
            UNSUPPORTED_PARSER_HINT,
        )
        if resolved_path is None:
            return ClassifiedTarget(
                id=str(uuid.uuid4()),
                artifact_type=target_spec.artifact_type,
                relative_path=target_spec.relative_path,
                classification="missing",
                resolved_path=None,
                parser_hint=parser_hint,
                reason="target path is outside the mounted evidence root",
            )
        if not resolved_path.exists() or not resolved_path.is_file():
            return ClassifiedTarget(
                id=str(uuid.uuid4()),
                artifact_type=target_spec.artifact_type,
                relative_path=target_spec.relative_path,
                classification="missing",
                resolved_path=None,
                parser_hint=parser_hint,
                reason="target path does not exist",
            )
        return ClassifiedTarget(
            id=str(uuid.uuid4()),
            artifact_type=target_spec.artifact_type,
            relative_path=target_spec.relative_path,
            classification="found",
            resolved_path=str(resolved_path),
            parser_hint=parser_hint,
            reason="",
        )

    def _normalize_source(self, row: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(row)
        normalized["metadata"] = loads(str(normalized.get("metadata") or ""), {})
        return normalized

    def _normalize_plan(self, row: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(row)
        targets = [self._normalize_target(target) for target in self.storage.list_plan_targets(str(row["id"]))]
        normalized["targets"] = targets
        normalized["found_count"] = sum(1 for target in targets if target["classification"] == "found")
        normalized["missing_count"] = sum(1 for target in targets if target["classification"] == "missing")
        return normalized

    def _normalize_target(self, row: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(row)
        normalized["parser_hint"] = loads(str(normalized.get("parser_hint") or ""), {})
        return normalized

    def _normalize_artifact(self, row: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(row)
        normalized["parser_hint"] = loads(str(normalized.get("parser_hint") or ""), {})
        return normalized


def _resolve_relative_path(root_path: Path, relative_path: str) -> Path | None:
    if PureWindowsPath(relative_path).is_absolute() or Path(relative_path).is_absolute():
        return None

    parts = [
        part
        for part in relative_path.replace("\\", "/").split("/")
        if part not in {"", "."}
    ]
    if any(part == ".." for part in parts):
        return None

    root_resolved = root_path.resolve()
    candidate = root_resolved.joinpath(*parts).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None
    return candidate


def _discover_targets(root_path: Path) -> list[CollectionTargetSpec]:
    discovered: list[CollectionTargetSpec] = []
    missing_types: set[str] = set()
    for artifact_type, pattern in DEFAULT_DISCOVERY_PATTERNS:
        matches = sorted(path for path in root_path.glob(pattern) if path.exists() and path.is_file())
        if matches:
            discovered.extend(
                CollectionTargetSpec(artifact_type=artifact_type, relative_path=_relative_to_source(root_path, match))
                for match in matches
            )
        else:
            missing_types.add(artifact_type)

    for artifact_type in sorted(missing_types):
        representative = next(pattern for known_type, pattern in DEFAULT_DISCOVERY_PATTERNS if known_type == artifact_type)
        discovered.append(CollectionTargetSpec(artifact_type=artifact_type, relative_path=_missing_pattern(representative)))
    return discovered


def _relative_to_source(root_path: Path, artifact_path: Path) -> str:
    return artifact_path.relative_to(root_path).as_posix()


def _missing_pattern(pattern: str) -> str:
    return pattern.replace("**", "<missing>").replace("*", "<missing>")
