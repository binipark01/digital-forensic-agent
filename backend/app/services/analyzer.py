from __future__ import annotations

import subprocess
import uuid
from pathlib import Path
from typing import Any

from app.database import Database, dumps
from app.services.analysis_types import AnalysisResult, NormalizedEvent, epoch_to_iso, utc_now
from app.services.forensics import parser_capabilities
from app.services.timeline_adapters import DfatoolMftAdapter, DfatoolUsnAdapter, SidecarTimelineAdapter


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
        self.dfatool_mft = DfatoolMftAdapter()
        self.dfatool_usn = DfatoolUsnAdapter()
        self.sidecar = SidecarTimelineAdapter()
        self.sleuthkit = SleuthKitFlsAdapter()

    def analyze(self, case_id: str, image: dict[str, Any], run_id: str, parser_mode: str) -> AnalysisResult:
        image_path = Path(image["path"])
        if parser_mode in {"auto", "dfatool_mft"} and self.dfatool_mft.can_run(image_path):
            return self.dfatool_mft.run(image)

        if parser_mode in {"auto", "dfatool_usn"} and self.dfatool_usn.can_run(image_path):
            return self.dfatool_usn.run(image)

        if parser_mode in {"auto", "sidecar"} and self.sidecar.can_run(image_path):
            return self.sidecar.run(image_path)

        if parser_mode == "sleuthkit" and self.sleuthkit.can_run(image_path):
            return self.sleuthkit.run(image_path)

        return AnalysisResult(
            events=[],
            parser_name="none",
            warning=(
                "No timeline parser ran. Provide an extracted NTFS $MFT or $UsnJrnl:$J file for dfatool, "
                "or add a sidecar timeline as fallback. Sleuth Kit is available only through "
                "explicit validation/comparison mode."
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
