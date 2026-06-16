from __future__ import annotations

import os
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from starlette.middleware import Middleware, _MiddlewareFactory
from starlette.middleware.cors import CORSMiddleware

from app import __version__
from app.collection_routes import register_collection_routes
from app.database import Database, dumps, loads
from app.schemas import (
    AnalysisRequest,
    AnalysisRunOut,
    CaseCreate,
    CaseOut,
    ImageOut,
    ImageRegister,
    RecommendationsOut,
    ReportOut,
    ReportRequest,
    TimelineResponse,
)
from app.services.artifact_analysis import ArtifactAnalysisService
from app.services.analyzer import AnalyzerService, utc_now
from app.services.forensics import detect_image_format, hash_file, parser_capabilities
from app.services.recommendations import build_recommendations
from app.services.reports import render_report, write_report
from app.storage import CollectionStorage

Receive = Callable[[], Awaitable[Any]]
Send = Callable[[Any], Awaitable[None]]
AsgiApp = Callable[[Any, Receive, Send], Awaitable[None]]


def default_db_path() -> Path:
    return Path(os.environ.get("DFAA_DB_PATH", Path(__file__).resolve().parents[1] / "data" / "dfaa.sqlite3"))


def cors_origins() -> list[str]:
    configured = os.environ.get("DFAA_CORS_ORIGINS")
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5174",
        "http://localhost:5174",
    ]


def cors_middleware(app: AsgiApp, /) -> AsgiApp:
    return CORSMiddleware(
        app,
        allow_origins=cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


cors_middleware_factory: _MiddlewareFactory[[]] = cors_middleware


def create_app(db_path: Path | str | None = None) -> FastAPI:
    db = Database(db_path or default_db_path())
    app = FastAPI(
        title="Digital Forensic Automation Agent",
        version=__version__,
        middleware=[Middleware(cors_middleware_factory)],
    )
    app.state.db = db

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/capabilities")
    def capabilities() -> dict[str, Any]:
        caps = parser_capabilities()
        caps["app_version"] = __version__
        return caps

    @app.post("/cases", response_model=CaseOut)
    def create_case(payload: CaseCreate, database: Database = Depends(get_db)) -> dict[str, Any]:
        case_id = str(uuid.uuid4())
        created_at = utc_now()
        database.execute(
            """
            INSERT INTO cases (id, name, examiner, description, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (case_id, payload.name, payload.examiner, payload.description, created_at),
        )
        return {
            "id": case_id,
            "name": payload.name,
            "examiner": payload.examiner,
            "description": payload.description,
            "created_at": created_at,
            "image_count": 0,
            "event_count": 0,
        }

    @app.get("/cases", response_model=list[CaseOut])
    def list_cases(database: Database = Depends(get_db)) -> list[dict[str, Any]]:
        return database.fetchall(
            """
            SELECT c.*,
                   COUNT(DISTINCT i.id) AS image_count,
                   COUNT(DISTINCT e.id) AS event_count
            FROM cases c
            LEFT JOIN images i ON i.case_id = c.id
            LEFT JOIN timeline_events e ON e.case_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
            """
        )

    @app.get("/cases/{case_id}", response_model=CaseOut)
    def get_case(case_id: str, database: Database = Depends(get_db)) -> dict[str, Any]:
        case = database.fetchone(
            """
            SELECT c.*,
                   COUNT(DISTINCT i.id) AS image_count,
                   COUNT(DISTINCT e.id) AS event_count
            FROM cases c
            LEFT JOIN images i ON i.case_id = c.id
            LEFT JOIN timeline_events e ON e.case_id = c.id
            WHERE c.id = ?
            GROUP BY c.id
            """,
            (case_id,),
        )
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        return case

    @app.post("/cases/{case_id}/images", response_model=ImageOut)
    def register_image(case_id: str, payload: ImageRegister, database: Database = Depends(get_db)) -> dict[str, Any]:
        require_case(database, case_id)
        image_path = Path(payload.path).expanduser()
        if not image_path.exists() or not image_path.is_file():
            raise HTTPException(status_code=400, detail="Image path does not exist or is not a file")

        hashes = hash_file(image_path)
        format_name, hints = detect_image_format(image_path)
        image_id = str(uuid.uuid4())
        registered_at = utc_now()
        database.execute(
            """
            INSERT INTO images (
                id, case_id, path, format, size_bytes, md5, sha1, sha256, registered_at, parser_hints
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                image_id,
                case_id,
                str(image_path.resolve()),
                format_name,
                image_path.stat().st_size,
                hashes["md5"],
                hashes["sha1"],
                hashes["sha256"],
                registered_at,
                dumps(hints),
            ),
        )
        return normalize_image(database.fetchone("SELECT * FROM images WHERE id = ?", (image_id,)))

    @app.get("/cases/{case_id}/images", response_model=list[ImageOut])
    def list_images(case_id: str, database: Database = Depends(get_db)) -> list[dict[str, Any]]:
        require_case(database, case_id)
        return [
            normalize_image(row)
            for row in database.fetchall("SELECT * FROM images WHERE case_id = ? ORDER BY registered_at DESC", (case_id,))
        ]

    @app.post("/cases/{case_id}/analysis", response_model=AnalysisRunOut)
    def start_analysis(case_id: str, payload: AnalysisRequest, database: Database = Depends(get_db)) -> dict[str, Any]:
        require_case(database, case_id)
        if payload.artifact_ids:
            try:
                return ArtifactAnalysisService(database).analyze(case_id, payload.artifact_ids, payload.parser_mode)
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        if payload.image_id is None:
            artifact_ids = [row["id"] for row in CollectionStorage(database).list_artifacts(case_id)]
            if artifact_ids:
                return ArtifactAnalysisService(database).analyze(case_id, artifact_ids, payload.parser_mode)
            latest_image = database.fetchone(
                "SELECT id FROM images WHERE case_id = ? ORDER BY registered_at DESC LIMIT 1",
                (case_id,),
            )
            if latest_image is None:
                return complete_without_processable_evidence(database, case_id, payload.parser_mode)

        image = resolve_image(database, case_id, payload.image_id)
        run_id = str(uuid.uuid4())
        started_at = utc_now()
        command_line = f"analyze --case {case_id} --image {image['id']} --parser-mode {payload.parser_mode}"
        tool_versions = parser_capabilities()
        database.execute(
            """
            INSERT INTO analysis_runs (
                id, case_id, image_id, status, parser_mode, started_at, command_line, tool_versions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                case_id,
                image["id"],
                "running",
                payload.parser_mode,
                started_at,
                command_line,
                dumps(tool_versions),
            ),
        )

        result = AnalyzerService(database).analyze(case_id, image, run_id, payload.parser_mode)
        event_count = AnalyzerService(database).persist_events(case_id, image["id"], run_id, result.events)
        completed_at = utc_now()
        warning = result.warning
        database.execute(
            """
            UPDATE analysis_runs
            SET status = ?, completed_at = ?, warning = ?, event_count = ?, tool_versions = ?
            WHERE id = ?
            """,
            (
                "completed" if not warning else "completed_with_warnings",
                completed_at,
                warning,
                event_count,
                dumps({**tool_versions, "selected_parser": result.parser_name}),
                run_id,
            ),
        )
        return normalize_run(database.fetchone("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)))

    @app.get("/cases/{case_id}/timeline", response_model=TimelineResponse)
    def timeline(
        case_id: str,
        source_artifact: str | None = None,
        action: str | None = None,
        path_query: str | None = Query(default=None, alias="path"),
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
        database: Database = Depends(get_db),
    ) -> dict[str, Any]:
        require_case(database, case_id)
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if source_artifact:
            where.append("source_artifact = ?")
            params.append(source_artifact)
        if action:
            where.append("action = ?")
            params.append(action)
        if path_query:
            where.append("path LIKE ?")
            params.append(f"%{path_query}%")

        where_sql = " AND ".join(where)
        total_row = database.fetchone(f"SELECT COUNT(*) AS count FROM timeline_events WHERE {where_sql}", params)
        total = total_row["count"] if total_row else 0
        rows = database.fetchall(
            f"""
            SELECT * FROM timeline_events
            WHERE {where_sql}
            ORDER BY COALESCE(timestamp, created_at) ASC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        )
        return {"events": [normalize_event(row) for row in rows], "total": total, "limit": limit, "offset": offset}

    @app.get("/cases/{case_id}/events/{event_id}")
    def event_detail(case_id: str, event_id: str, database: Database = Depends(get_db)) -> dict[str, Any]:
        require_case(database, case_id)
        event = database.fetchone("SELECT * FROM timeline_events WHERE case_id = ? AND id = ?", (case_id, event_id))
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        return normalize_event(event)

    @app.get("/cases/{case_id}/recommendations", response_model=RecommendationsOut)
    def recommendations(case_id: str, database: Database = Depends(get_db)) -> dict[str, Any]:
        require_case(database, case_id)
        events = [normalize_event(row) for row in fetch_all_events(database, case_id)]
        return {
            "recommendations": build_recommendations(events),
            "generated_from_event_count": len(events),
        }

    @app.post("/cases/{case_id}/reports", response_model=ReportOut)
    def create_report(case_id: str, payload: ReportRequest, database: Database = Depends(get_db)) -> dict[str, Any]:
        case = require_case(database, case_id)
        events = [normalize_event(row) for row in fetch_all_events(database, case_id)]
        content = render_report(payload.format, case, events)
        report_id = str(uuid.uuid4())
        output_path = write_report(
            Path(database.path).parent / "reports" / case_id,
            report_id,
            payload.format,
            content,
        )
        generated_at = utc_now()
        preview = content[:800]
        database.execute(
            """
            INSERT INTO reports (id, case_id, format, path, generated_at, event_count, content_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (report_id, case_id, payload.format, str(output_path), generated_at, len(events), preview),
        )
        report = database.fetchone("SELECT * FROM reports WHERE id = ?", (report_id,))
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report

    @app.get("/cases/{case_id}/reports", response_model=list[ReportOut])
    def list_reports(case_id: str, database: Database = Depends(get_db)) -> list[dict[str, Any]]:
        require_case(database, case_id)
        return database.fetchall("SELECT * FROM reports WHERE case_id = ? ORDER BY generated_at DESC", (case_id,))

    register_collection_routes(app, get_db, require_case)
    return app


def get_db(request: Request) -> Database:
    return request.app.state.db


def require_case(database: Database, case_id: str) -> dict[str, Any]:
    case = database.fetchone("SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def resolve_image(database: Database, case_id: str, image_id: str | None) -> dict[str, Any]:
    if image_id:
        image = database.fetchone("SELECT * FROM images WHERE id = ? AND case_id = ?", (image_id, case_id))
    else:
        image = database.fetchone(
            "SELECT * FROM images WHERE case_id = ? ORDER BY registered_at DESC LIMIT 1",
            (case_id,),
        )
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")
    return normalize_image(image)


def complete_without_processable_evidence(database: Database, case_id: str, parser_mode: str) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    now = utc_now()
    message = "No evidence artifacts, sidecar timeline artifact, or image fallback were available for analysis."
    warning = {"code": "no_processable_evidence", "message": message}
    database.execute(
        """
        INSERT INTO analysis_runs (
            id, case_id, image_id, artifact_id, status, parser_mode, started_at,
            completed_at, command_line, tool_versions, warning, warnings, event_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            case_id,
            None,
            None,
            "completed_with_warnings",
            parser_mode,
            now,
            now,
            f"analyze --case {case_id} --parser-mode {parser_mode}",
            dumps({**parser_capabilities(), "selected_parser": None}),
            message,
            dumps([warning]),
            0,
        ),
    )
    return normalize_run(database.fetchone("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)))


def fetch_all_events(database: Database, case_id: str) -> list[dict[str, Any]]:
    return database.fetchall(
        """
        SELECT * FROM timeline_events
        WHERE case_id = ?
        ORDER BY COALESCE(timestamp, created_at) ASC
        """,
        (case_id,),
    )


def normalize_image(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        raise HTTPException(status_code=404, detail="Image not found")
    normalized = dict(row)
    normalized["parser_hints"] = loads(normalized["parser_hints"], {})
    return normalized


def normalize_run(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    normalized = dict(row)
    normalized["tool_versions"] = loads(normalized["tool_versions"], {})
    normalized["warnings"] = loads(normalized.get("warnings"), [])
    return normalized


def normalize_event(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized["provenance"] = loads(normalized["provenance"], {})
    normalized["attributes"] = loads(normalized["attributes"], {})
    return normalized


app = create_app()
