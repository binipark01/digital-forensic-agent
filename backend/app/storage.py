from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.database import Database, dumps
from app.models import AnalysisWarning, ClassifiedTarget, FileHashes


class CollectionStorage:
    def __init__(self, db: Database):
        self.db = db

    def case_exists(self, case_id: str) -> bool:
        return self.db.fetchone("SELECT id FROM cases WHERE id = ?", (case_id,)) is not None

    def insert_source(
        self,
        source_id: str,
        case_id: str,
        name: str,
        source_type: str,
        root_path: str,
        registered_at: str,
    ) -> dict[str, Any]:
        self.db.execute(
            """
            INSERT INTO evidence_sources (id, case_id, name, source_type, root_path, registered_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (source_id, case_id, name, source_type, root_path, registered_at, dumps({})),
        )
        return self.require_source(case_id, source_id)

    def require_source(self, case_id: str, source_id: str) -> dict[str, Any]:
        source = self.db.fetchone(
            "SELECT * FROM evidence_sources WHERE case_id = ? AND id = ?",
            (case_id, source_id),
        )
        if source is None:
            raise LookupError("evidence source not found")
        return source

    def list_sources(self, case_id: str) -> list[dict[str, Any]]:
        return self.db.fetchall(
            "SELECT * FROM evidence_sources WHERE case_id = ? ORDER BY registered_at DESC",
            (case_id,),
        )

    def insert_plan(
        self,
        plan_id: str,
        case_id: str,
        source_id: str,
        name: str,
        created_at: str,
        targets: Iterable[ClassifiedTarget],
    ) -> dict[str, Any]:
        self.db.execute(
            """
            INSERT INTO collection_plans (
                id, case_id, evidence_source_id, name, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (plan_id, case_id, source_id, name, "planned", created_at),
        )
        rows = [
            (
                target.id,
                plan_id,
                target.artifact_type,
                target.relative_path,
                target.resolved_path,
                target.classification,
                dumps(target.parser_hint),
                target.reason,
            )
            for target in targets
        ]
        self.db.executemany(
            """
            INSERT INTO collection_targets (
                id, plan_id, artifact_type, relative_path, resolved_path, classification, parser_hint, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        return self.require_plan(case_id, plan_id)

    def require_plan(self, case_id: str, plan_id: str) -> dict[str, Any]:
        plan = self.db.fetchone(
            "SELECT * FROM collection_plans WHERE case_id = ? AND id = ?",
            (case_id, plan_id),
        )
        if plan is None:
            raise LookupError("collection plan not found")
        return plan

    def list_plan_targets(self, plan_id: str) -> list[dict[str, Any]]:
        return self.db.fetchall(
            "SELECT * FROM collection_targets WHERE plan_id = ? ORDER BY rowid ASC",
            (plan_id,),
        )

    def list_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        return self.db.fetchall(
            "SELECT * FROM evidence_artifacts WHERE case_id = ? ORDER BY registered_at DESC",
            (case_id,),
        )

    def fetch_artifacts(self, case_id: str, artifact_ids: list[str]) -> list[dict[str, Any]]:
        if not artifact_ids:
            return []
        placeholders = ",".join("?" for _ in artifact_ids)
        rows = self.db.fetchall(
            f"""
            SELECT * FROM evidence_artifacts
            WHERE case_id = ? AND id IN ({placeholders})
            """,
            (case_id, *artifact_ids),
        )
        by_id = {row["id"]: row for row in rows}
        return [by_id[artifact_id] for artifact_id in artifact_ids if artifact_id in by_id]

    def insert_artifact(
        self,
        artifact_id: str,
        case_id: str,
        source_id: str,
        plan_id: str,
        target_id: str,
        artifact_type: str,
        path: str,
        size_bytes: int,
        hashes: FileHashes,
        parser_hint: dict[str, Any],
        registered_at: str,
    ) -> dict[str, Any]:
        self.db.execute(
            """
            INSERT INTO evidence_artifacts (
                id, case_id, evidence_source_id, collection_plan_id, collection_target_id,
                artifact_type, path, size_bytes, md5, sha1, sha256, parser_hint, registered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                case_id,
                source_id,
                plan_id,
                target_id,
                artifact_type,
                path,
                size_bytes,
                hashes.md5,
                hashes.sha1,
                hashes.sha256,
                dumps(parser_hint),
                registered_at,
            ),
        )
        return self.db.fetchone("SELECT * FROM evidence_artifacts WHERE id = ?", (artifact_id,)) or {}

    def mark_plan_executed(self, plan_id: str, executed_at: str, artifact_count: int) -> None:
        self.db.execute(
            """
            UPDATE collection_plans
            SET status = ?, executed_at = ?, registered_artifact_count = ?
            WHERE id = ?
            """,
            ("completed", executed_at, artifact_count, plan_id),
        )


def warning_to_dict(warning: AnalysisWarning) -> dict[str, str]:
    return {
        "code": warning.code,
        "artifact_id": warning.artifact_id,
        "artifact_type": warning.artifact_type,
        "message": warning.message,
    }
