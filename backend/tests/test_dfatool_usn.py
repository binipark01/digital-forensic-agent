from __future__ import annotations

import json
from pathlib import Path

from dfatool.cli import main as dfatool_main
from dfatool.usn import build_timeline_events, parse_usn_file

from tests.fixtures_usn import synthetic_usn_bytes


def write_fixture(tmp_path: Path, *, include_malformed: bool = False) -> Path:
    path = tmp_path / "$UsnJrnl_J"
    path.write_bytes(synthetic_usn_bytes(include_malformed=include_malformed))
    return path


def test_parse_synthetic_usn_v2_records(tmp_path: Path) -> None:
    # Given: a synthetic extracted $UsnJrnl:$J stream with V2 records.
    usn_path = write_fixture(tmp_path)

    # When: dfatool parses the journal file directly.
    result = parse_usn_file(usn_path)

    # Then: record fields, reason flags, and file references are preserved.
    assert result.artifact_hash
    assert len(result.records) == 5
    created = result.records[0]
    deleted_dir = result.records[4]
    assert created.record_length > 60
    assert created.major_version == 2
    assert created.file_reference_number == 1970324836974634
    assert created.file_reference.entry == 42
    assert created.file_reference.sequence == 7
    assert created.parent_file_reference.entry == 5
    assert created.usn == 100
    assert created.timestamp == "2026-03-01T00:00:00+00:00"
    assert created.reason_flags == ["FILE_CREATE"]
    assert created.file_name == "created.txt"
    assert created.record_offset == 0
    assert deleted_dir.is_directory is True


def test_usn_timeline_maps_reason_flags_to_actions(tmp_path: Path) -> None:
    # Given: USN records covering create, delete, rename, content, and security changes.
    result = parse_usn_file(write_fixture(tmp_path))

    # When: the parser emits normalized timeline events.
    events = build_timeline_events(result)

    # Then: the requested action mapping and provenance are present.
    actions = {(event["record_id"], event["action"]) for event in events}
    assert ("100", "file_created") in actions
    assert ("120", "file_content_modified") in actions
    assert ("130", "file_rename_old_name") in actions
    assert ("140", "file_rename_new_name") in actions
    assert ("150", "file_deleted") in actions
    assert ("150", "file_security_modified") in actions

    created = next(event for event in events if event["action"] == "file_created")
    assert created["source_artifact"] == "NTFS:$UsnJrnl:$J"
    assert created["path"] == "created.txt"
    assert created["provenance"]["artifact_sha256"] == result.artifact_hash
    assert created["provenance"]["parser_name"] == "dfatool.usn"
    assert created["provenance"]["parser_version"]
    assert created["provenance"]["record_offset"] == 0
    assert created["provenance"]["usn"] == 100
    assert created["provenance"]["file_reference_number"] == 1970324836974634
    assert created["provenance"]["parent_file_reference_number"] == 281474976710661
    assert created["provenance"]["raw_reason"] == 0x100
    assert created["provenance"]["reason_flags"] == ["FILE_CREATE"]
    assert created["attributes"]["timestamp_source"] == "$UsnJrnl:$J"
    assert created["attributes"]["path_confidence"] == "low"


def test_malformed_usn_record_warns_without_stopping_valid_neighbors(tmp_path: Path) -> None:
    # Given: a valid journal with one malformed short record between valid records.
    result = parse_usn_file(write_fixture(tmp_path, include_malformed=True))

    # When: timeline events are generated from the surviving records.
    events = build_timeline_events(result)

    # Then: the malformed record is a warning, not an analysis stopper.
    assert len(result.records) == 5
    assert any("record length 8 is too small" in warning for warning in result.warnings)
    assert any(event["record_id"] == "150" and event["action"] == "file_deleted" for event in events)


def test_dfatool_cli_usn_parse_and_timeline(tmp_path: Path) -> None:
    # Given: a synthetic USN journal and output paths.
    usn_path = write_fixture(tmp_path)
    json_path = tmp_path / "usn-records.jsonl"
    csv_path = tmp_path / "usn-records.csv"
    timeline_path = tmp_path / "usn-timeline.jsonl"

    # When: the dfatool USN CLI parse and timeline commands run.
    assert dfatool_main(["usn", "parse", "--input", str(usn_path), "--json", str(json_path), "--csv", str(csv_path)]) == 0
    assert dfatool_main(["usn", "timeline", "--input", str(usn_path), "--output", str(timeline_path)]) == 0

    # Then: records and timeline JSONL are written with USN-specific fields.
    records = [json.loads(line) for line in json_path.read_text(encoding="utf-8").splitlines()]
    events = [json.loads(line) for line in timeline_path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["file_name"] == "created.txt"
    assert records[0]["reason_flags"] == ["FILE_CREATE"]
    assert "usn,file_reference_number,parent_file_reference_number" in csv_path.read_text(encoding="utf-8")
    assert any(event["source_artifact"] == "NTFS:$UsnJrnl:$J" for event in events)


def test_synthetic_usn_timeline_golden_output(tmp_path: Path) -> None:
    # Given: the fixed synthetic USN journal.
    result = parse_usn_file(write_fixture(tmp_path))

    # When: timeline events are projected to the stable report-facing fields.
    events = build_timeline_events(result)
    projected = [
        {
            "timestamp": event["timestamp"],
            "source_artifact": event["source_artifact"],
            "record_id": event["record_id"],
            "path": event["path"],
            "action": event["action"],
            "usn": event["provenance"]["usn"],
            "reason_flags": event["provenance"]["reason_flags"],
        }
        for event in events
        if event["action"]
        in {
            "file_created",
            "file_deleted",
            "file_rename_old_name",
            "file_rename_new_name",
            "file_content_modified",
        }
    ]

    # Then: the output remains stable for future parser changes.
    assert projected == [
        {
            "timestamp": "2026-03-01T00:00:00+00:00",
            "source_artifact": "NTFS:$UsnJrnl:$J",
            "record_id": "100",
            "path": "created.txt",
            "action": "file_created",
            "usn": 100,
            "reason_flags": ["FILE_CREATE"],
        },
        {
            "timestamp": "2026-03-01T00:01:00+00:00",
            "source_artifact": "NTFS:$UsnJrnl:$J",
            "record_id": "120",
            "path": "modified.bin",
            "action": "file_content_modified",
            "usn": 120,
            "reason_flags": ["DATA_EXTEND", "CLOSE"],
        },
        {
            "timestamp": "2026-03-01T00:02:00+00:00",
            "source_artifact": "NTFS:$UsnJrnl:$J",
            "record_id": "130",
            "path": "old-name.docx",
            "action": "file_rename_old_name",
            "usn": 130,
            "reason_flags": ["RENAME_OLD_NAME"],
        },
        {
            "timestamp": "2026-03-01T00:02:01+00:00",
            "source_artifact": "NTFS:$UsnJrnl:$J",
            "record_id": "140",
            "path": "new-name.docx",
            "action": "file_rename_new_name",
            "usn": 140,
            "reason_flags": ["RENAME_NEW_NAME"],
        },
        {
            "timestamp": "2026-03-01T00:03:00+00:00",
            "source_artifact": "NTFS:$UsnJrnl:$J",
            "record_id": "150",
            "path": "deleted-dir",
            "action": "file_deleted",
            "usn": 150,
            "reason_flags": ["FILE_DELETE", "SECURITY_CHANGE"],
        },
    ]
