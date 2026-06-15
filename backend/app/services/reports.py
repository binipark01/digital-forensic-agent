from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any

from app.services.recommendations import build_recommendations


def render_report(format_name: str, case: dict[str, Any], events: list[dict[str, Any]]) -> str:
    if format_name == "json":
        return json.dumps(
            {"case": case, "events": events, "recommendations": build_recommendations(events)},
            ensure_ascii=False,
            indent=2,
        )
    if format_name == "csv":
        return _render_csv(events)
    return _render_markdown(case, events)


def report_extension(format_name: str) -> str:
    return {"markdown": "md", "json": "json", "csv": "csv"}[format_name]


def write_report(base_dir: Path, report_id: str, format_name: str, content: str) -> Path:
    base_dir.mkdir(parents=True, exist_ok=True)
    path = base_dir / f"{report_id}.{report_extension(format_name)}"
    path.write_text(content, encoding="utf-8", newline="")
    return path


def _render_csv(events: list[dict[str, Any]]) -> str:
    handle = StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "source_artifact",
        "record_id",
        "path",
        "action",
        "confidence",
        "provenance",
    ]
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                key: json.dumps(event[key], ensure_ascii=False)
                if key == "provenance"
                else event.get(key)
                for key in fieldnames
            }
        )
    return handle.getvalue()


def _render_markdown(case: dict[str, Any], events: list[dict[str, Any]]) -> str:
    recommendations = build_recommendations(events)
    lines = [
        f"# Forensic Timeline Report: {case['name']}",
        "",
        f"- Case ID: `{case['id']}`",
        f"- Examiner: {case.get('examiner') or 'Unassigned'}",
        f"- Event count: {len(events)}",
        "",
        "## Evidence-Based Recommendations",
        "",
    ]

    for recommendation in recommendations:
        evidence = ", ".join(f"`{event_id}`" for event_id in recommendation["evidence_event_ids"])
        lines.extend(
            [
                f"### {recommendation['title']}",
                recommendation["rationale"],
                "",
                f"Evidence events: {evidence or 'none'}",
                "",
            ]
        )

    lines.extend(["## Timeline Sample", ""])
    for event in events[:50]:
        lines.append(
            f"- `{event['timestamp'] or 'unknown time'}` {event['action']} "
            f"`{event['path']}` from {event['source_artifact']} "
            f"(confidence {event['confidence']:.2f}, event `{event['id']}`)"
        )

    return "\n".join(lines) + "\n"

