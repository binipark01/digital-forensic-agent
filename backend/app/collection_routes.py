from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Request

from app.database import Database
from app.schemas import (
    CollectionExecutionOut,
    CollectionPlanCreate,
    CollectionPlanOut,
    CollectionTargetOut,
    EvidenceArtifactOut,
    EvidenceArtifactsOut,
    EvidenceSourceCreate,
    EvidenceSourceOut,
)
from app.services.collection import CollectionService, RequestedTarget


GetDb = Callable[[Request], Database]
RequireCase = Callable[[Database, str], dict[str, Any]]


def register_collection_routes(app: FastAPI, get_db: GetDb, require_case: RequireCase) -> None:
    @app.post("/cases/{case_id}/evidence-sources", response_model=EvidenceSourceOut)
    @app.post("/cases/{case_id}/sources", response_model=EvidenceSourceOut)
    def create_evidence_source(
        case_id: str,
        payload: EvidenceSourceCreate,
        database: Database = Depends(get_db),
    ) -> dict[str, Any]:
        require_case(database, case_id)
        raw_path = payload.root_path or payload.path
        if not raw_path:
            raise HTTPException(status_code=422, detail="root_path or path is required")
        root_path = Path(raw_path).expanduser()
        if not root_path.exists() or not root_path.is_dir():
            raise HTTPException(status_code=400, detail="Evidence source path must be an existing directory")
        source_name = payload.name or payload.label or root_path.name or "Evidence source"
        return CollectionService(database).create_source(case_id, source_name, payload.source_type, root_path)

    @app.get("/cases/{case_id}/evidence-sources", response_model=list[EvidenceSourceOut])
    @app.get("/cases/{case_id}/sources", response_model=list[EvidenceSourceOut])
    def list_evidence_sources(case_id: str, database: Database = Depends(get_db)) -> list[dict[str, Any]]:
        require_case(database, case_id)
        return CollectionService(database).list_sources(case_id)

    @app.post("/cases/{case_id}/collection-plans", response_model=CollectionPlanOut)
    def create_collection_plan(
        case_id: str,
        payload: CollectionPlanCreate,
        database: Database = Depends(get_db),
    ) -> dict[str, Any]:
        require_case(database, case_id)
        if not payload.evidence_source_id:
            raise HTTPException(status_code=422, detail="evidence_source_id is required")
        targets = [
            RequestedTarget(artifact_type=target.artifact_type, relative_path=target.relative_path)
            for target in payload.targets or []
        ]
        try:
            return CollectionService(database).create_plan(
                case_id,
                payload.evidence_source_id,
                payload.name,
                targets or None,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/cases/{case_id}/sources/{source_id}/collection-plans", response_model=CollectionPlanOut)
    @app.post("/cases/{case_id}/sources/{source_id}/plans", response_model=CollectionPlanOut)
    def create_discovered_collection_plan(
        case_id: str,
        source_id: str,
        payload: CollectionPlanCreate | None = None,
        database: Database = Depends(get_db),
    ) -> dict[str, Any]:
        require_case(database, case_id)
        plan_name = payload.name if payload else "Windows triage collection plan"
        targets = [
            RequestedTarget(artifact_type=target.artifact_type, relative_path=target.relative_path)
            for target in (payload.targets if payload and payload.targets else [])
        ]
        try:
            return CollectionService(database).create_plan(case_id, source_id, plan_name, targets or None)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/cases/{case_id}/collection-plans/{plan_id}/targets", response_model=list[CollectionTargetOut])
    def list_collection_targets(
        case_id: str,
        plan_id: str,
        database: Database = Depends(get_db),
    ) -> list[dict[str, Any]]:
        require_case(database, case_id)
        try:
            return CollectionService(database).list_targets(case_id, plan_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/cases/{case_id}/collection-plans/{plan_id}/execute", response_model=CollectionExecutionOut)
    def execute_collection_plan(
        case_id: str,
        plan_id: str,
        database: Database = Depends(get_db),
    ) -> dict[str, Any]:
        require_case(database, case_id)
        try:
            return CollectionService(database).execute_plan(case_id, plan_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/cases/{case_id}/evidence-artifacts", response_model=EvidenceArtifactsOut)
    def list_evidence_artifacts(case_id: str, database: Database = Depends(get_db)) -> dict[str, list[dict[str, Any]]]:
        require_case(database, case_id)
        return {"artifacts": CollectionService(database).list_artifacts(case_id)}

    @app.get("/cases/{case_id}/artifacts", response_model=list[EvidenceArtifactOut])
    def list_evidence_artifacts_alias(case_id: str, database: Database = Depends(get_db)) -> list[dict[str, Any]]:
        require_case(database, case_id)
        return CollectionService(database).list_artifacts(case_id)

    @app.get("/cases/{case_id}/evidence-artifacts/{artifact_id}", response_model=EvidenceArtifactOut)
    def get_evidence_artifact(
        case_id: str,
        artifact_id: str,
        database: Database = Depends(get_db),
    ) -> dict[str, Any]:
        require_case(database, case_id)
        try:
            return CollectionService(database).get_artifact(case_id, artifact_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
