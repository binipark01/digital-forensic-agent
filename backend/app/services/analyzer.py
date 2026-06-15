from __future__ import annotations

import csv
import json
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.database import Database, dumps
from app.services.forensics import parser_capabilities


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
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("events", payload if isinstance(payload, list) else [])
        return [self._event_from_mapping(row, str(path)) for row in rows]

    def _read_csv(self, path: Path) -> list[NormalizedEvent]:
        with path.open("r", encoding="utf-8", newline="") as handle:
            return [self._event_from_mapping(row, str(path)) for row in csv.DictReader(handle)]

    def _event_from_mapping(self, row: dict[str, Any], source_path: str) -> NormalizedEvent:
        provenance = row.get("provenance") or {}
        if isinstance(provenance, str):
            try:
                provenance = json.loads(provenance)
            except json.JSONDecodeError:
                provenance = {"raw": provenance}
        provenance.setdefault("parser", self.name)
        provenance.setdefault("source_path", source_path)

        attributes = row.get("attributes") or {}
        if isinstance(attributes, str):
            try:
                attributes = json.loads(attributes)
            except json.JSONDecodeError:
                attributes = {"raw": attributes}

        return NormalizedEvent(
            timestamp=row.get("timestamp") or None,
            source_artifact=row.get("source_artifact") or "$MFT",
            record_id=str(row.get("record_id") or ""),
            path=row.get("path") or "",
            action=row.get("action") or "observed",
            confidence=float(row.get("confidence") or 0.75),
            provenance=provenance,
            attributes=attributes,
        )


class SleuthKitFlsAdapter:
    name = "sleuthkit_fls"

    def can_run(self, image_path: Path) -> bool:
        caps = parser_capabilities()
        return bool(caps["commands"]["fls"]) and image_path.exists()

    def run(self, image_path: Path) -> AnalysisResult:
        offset = self._detect_ntfs_offset(image_path)
        command = ["fls", "-r", "-m", "/", "-p"]
        if offset is not None:
            command.extend(["-o", str(offset)])
        command.append(str(image_path))

        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if completed.returncode != 0:
            return AnalysisResult(
                [],
                self.name,
                f"Sleuth Kit fls failed: {completed.stderr.strip() or completed.stdout.strip()}",
            )

        events = self._parse_bodyfile(completed.stdout, image_path, offset)
        return AnalysisResult(events, self.name)

    def _detect_ntfs_offset(self, image_path: Path) -> int | None:
        caps = parser_capabilities()
        if not caps["commands"]["mmls"]:
            return None

        completed = subprocess.run(
            ["mmls", str(image_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            return None

        for line in completed.stdout.splitlines():
            lowered = line.lower()
            if "ntfs" not in lowered and "basic data" not in lowered:
                continue
            parts = line.split()
            for part in parts:
                if part.isdigit():
                    # mmls rows are slot, start, end, length, description.
                    # The first large numeric field after the slot is the sector offset.
                    if int(part) > 0:
                        return int(part)
        return None

    def _parse_bodyfile(
        self, bodyfile: str, image_path: Path, offset: int | None
    ) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        time_fields = [
            ("accessed", 7, "$STANDARD_INFORMATION"),
            ("modified", 8, "$STANDARD_INFORMATION"),
            ("metadata_changed", 9, "$STANDARD_INFORMATION"),
            ("created", 10, "$FILE_NAME"),
        ]

        for line_number, line in enumerate(bodyfile.splitlines(), start=1):
            parts = line.split("|")
            if len(parts) < 11:
                continue

            raw_name = parts[1].strip()
            is_deleted = raw_name.startswith("*")
            normalized_path = raw_name.lstrip("* ").replace("\\", "/")
            record_id = parts[2].strip()
            size = parts[6].strip()

            for action, index, attribute in time_fields:
                timestamp = epoch_to_iso(parts[index])
                if not timestamp:
                    continue
                events.append(
                    NormalizedEvent(
                        timestamp=timestamp,
                        source_artifact="$MFT",
                        record_id=record_id,
                        path=normalized_path,
                        action=action,
                        confidence=0.92,
                        provenance={
                            "parser": self.name,
                            "tool": "fls",
                            "image_path": str(image_path),
                            "volume_offset": offset,
                            "bodyfile_line": line_number,
                            "attribute": attribute,
                        },
                        attributes={
                            "size": size,
                            "is_deleted": is_deleted,
                            "mode": parts[3].strip(),
                        },
                    )
                )

            if is_deleted:
                events.append(
                    NormalizedEvent(
                        timestamp=epoch_to_iso(parts[9]) or epoch_to_iso(parts[8]),
                        source_artifact="$MFT",
                        record_id=record_id,
                        path=normalized_path,
                        action="deleted_record_seen",
                        confidence=0.78,
                        provenance={
                            "parser": self.name,
                            "tool": "fls",
                            "image_path": str(image_path),
                            "volume_offset": offset,
                            "bodyfile_line": line_number,
                            "attribute": "directory_entry",
                        },
                        attributes={"size": size, "is_deleted": True},
                    )
                )

        return events


class AnalyzerService:
    def __init__(self, db: Database):
        self.db = db
        self.sidecar = SidecarTimelineAdapter()
        self.sleuthkit = SleuthKitFlsAdapter()

    def analyze(self, case_id: str, image: dict[str, Any], run_id: str, parser_mode: str) -> AnalysisResult:
        image_path = Path(image["path"])
        if parser_mode in {"auto", "sidecar"} and self.sidecar.can_run(image_path):
            return self.sidecar.run(image_path)

        if parser_mode in {"auto", "sleuthkit"} and self.sleuthkit.can_run(image_path):
            return self.sleuthkit.run(image_path)

        return AnalysisResult(
            events=[],
            parser_name="none",
            warning=(
                "No timeline parser ran. Add a sidecar timeline or install Sleuth Kit CLI "
                "tools (`mmls`, `fls`) for direct image traversal."
            ),
        )

    def persist_events(
        self,
        case_id: str,
        image_id: str,
        run_id: str,
        events: list[NormalizedEvent],
    ) -> int:
        created_at = utc_now()
        rows = []
        for event in events:
            rows.append(
                (
                    str(uuid.uuid4()),
                    case_id,
                    image_id,
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
                id, case_id, image_id, run_id, timestamp, source_artifact,
                record_id, path, action, confidence, provenance, attributes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        return len(rows)

