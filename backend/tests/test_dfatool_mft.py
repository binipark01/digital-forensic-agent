from __future__ import annotations

import json
from pathlib import Path

from dfatool.cli import main as dfatool_main
from dfatool.mft import build_timeline_events, dump_record, parse_mft_file

from tests.fixtures_mft import synthetic_mft_bytes


def write_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "$MFT"
    path.write_bytes(synthetic_mft_bytes())
    return path


def test_parse_synthetic_mft_records(tmp_path: Path) -> None:
    mft_path = write_fixture(tmp_path)

    result = parse_mft_file(mft_path)

    assert result.artifact_hash
    assert len(result.records) == 4
    report = result.records[2]
    deleted = result.records[3]

    assert report.entry == 2
    assert report.sequence_number == 7
    assert report.active is True
    assert report.is_directory is False
    assert report.path == "/Users/report.txt"
    assert report.standard_information[0].timestamps.created == "2026-01-01T00:00:02+00:00"
    assert report.file_names[0].timestamps.created == "2026-02-01T00:00:00+00:00"
    assert report.file_names[0].parent_reference.entry == 1
    assert report.data_attributes[0].is_ads is False

    assert deleted.is_deleted is True
    assert deleted.path == "/Users/deleted.txt"
    assert any(stream.is_ads and stream.name == "Zone.Identifier" for stream in deleted.data_attributes)


def test_timeline_events_include_required_mft_provenance(tmp_path: Path) -> None:
    result = parse_mft_file(write_fixture(tmp_path))
    events = build_timeline_events(result)

    assert any(event["action"] == "si_created" for event in events)
    assert any(event["action"] == "fn_created" for event in events)
    deleted = next(event for event in events if event["action"] == "deleted_record_seen")
    ads = next(event for event in events if event["action"] == "ads_detected")

    assert deleted["source_artifact"] == "NTFS:$MFT"
    assert deleted["path"] == "/Users/deleted.txt"
    assert deleted["provenance"]["artifact_hash"] == result.artifact_hash
    assert deleted["provenance"]["mft_entry"] == 3
    assert deleted["provenance"]["sequence_number"] == 9
    assert deleted["provenance"]["record_offset"] == 3072
    assert deleted["provenance"]["attribute_offset"] is not None
    assert ads["attributes"]["stream_name"] == "Zone.Identifier"


def test_dump_record_returns_single_record(tmp_path: Path) -> None:
    result = parse_mft_file(write_fixture(tmp_path))

    payload = dump_record(result, 2)

    assert payload["record"]["record_id"] == "2-7"
    assert payload["record"]["path"] == "/Users/report.txt"


def test_dfatool_cli_parse_timeline_and_dump(tmp_path: Path, capsys) -> None:
    mft_path = write_fixture(tmp_path)
    json_path = tmp_path / "records.jsonl"
    csv_path = tmp_path / "records.csv"
    timeline_path = tmp_path / "timeline.jsonl"

    assert dfatool_main(["mft", "parse", "--input", str(mft_path), "--json", str(json_path), "--csv", str(csv_path)]) == 0
    assert dfatool_main(["mft", "timeline", "--input", str(mft_path), "--output", str(timeline_path)]) == 0
    assert dfatool_main(["mft", "dump-record", "--input", str(mft_path), "--entry", "2"]) == 0

    records = [json.loads(line) for line in json_path.read_text(encoding="utf-8").splitlines()]
    events = [json.loads(line) for line in timeline_path.read_text(encoding="utf-8").splitlines()]
    dumped = json.loads(capsys.readouterr().out)

    assert records[2]["path"] == "/Users/report.txt"
    assert "entry,sequence_number,record_offset" in csv_path.read_text(encoding="utf-8")
    assert any(event["source_artifact"] == "NTFS:$MFT" for event in events)
    assert dumped["record"]["entry"] == 2


def test_synthetic_timeline_golden_output(tmp_path: Path) -> None:
    result = parse_mft_file(write_fixture(tmp_path))
    events = build_timeline_events(result)
    golden = [
        {
            "timestamp": "2026-01-01T00:00:02+00:00",
            "source_artifact": "NTFS:$MFT",
            "record_id": "2-7",
            "path": "/Users/report.txt",
            "action": "si_created",
            "mft_entry": 2,
            "attribute_type": "$STANDARD_INFORMATION",
        },
        {
            "timestamp": "2026-02-01T00:00:00+00:00",
            "source_artifact": "NTFS:$MFT",
            "record_id": "2-7",
            "path": "/Users/report.txt",
            "action": "fn_created",
            "mft_entry": 2,
            "attribute_type": "$FILE_NAME",
        },
        {
            "timestamp": "2026-02-03T00:00:00+00:00",
            "source_artifact": "NTFS:$MFT",
            "record_id": "3-9",
            "path": "/Users/deleted.txt",
            "action": "deleted_record_seen",
            "mft_entry": 3,
            "attribute_type": "$FILE_NAME",
        },
        {
            "timestamp": "2026-01-03T00:00:03+00:00",
            "source_artifact": "NTFS:$MFT",
            "record_id": "3-9",
            "path": "/Users/deleted.txt",
            "action": "ads_detected",
            "mft_entry": 3,
            "attribute_type": "$DATA",
        },
    ]
    projected = [
        {
            "timestamp": event["timestamp"],
            "source_artifact": event["source_artifact"],
            "record_id": event["record_id"],
            "path": event["path"],
            "action": event["action"],
            "mft_entry": event["provenance"]["mft_entry"],
            "attribute_type": event["provenance"]["attribute_type"],
        }
        for event in events
        if (event["record_id"], event["action"]) in {
            ("2-7", "si_created"),
            ("2-7", "fn_created"),
            ("3-9", "deleted_record_seen"),
            ("3-9", "ads_detected"),
        }
    ]

    assert projected == golden

