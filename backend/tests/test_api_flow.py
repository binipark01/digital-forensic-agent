from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from tests.fixtures_mft import synthetic_mft_bytes


def test_case_image_analysis_timeline_report_flow(tmp_path: Path) -> None:
    image = tmp_path / "$MFT"
    image.write_bytes(synthetic_mft_bytes())

    client = TestClient(create_app(tmp_path / "test.sqlite3"))

    case_response = client.post("/cases", json={"name": "Test Case", "examiner": "Analyst"})
    assert case_response.status_code == 200
    case_id = case_response.json()["id"]

    image_response = client.post(f"/cases/{case_id}/images", json={"path": str(image)})
    assert image_response.status_code == 200
    image_payload = image_response.json()
    assert image_payload["format"] == "ntfs_mft"
    assert image_payload["sha256"]

    analysis_response = client.post(f"/cases/{case_id}/analysis", json={"image_id": image_payload["id"]})
    assert analysis_response.status_code == 200
    analysis_payload = analysis_response.json()
    assert analysis_payload["status"] == "completed"
    assert analysis_payload["event_count"] > 1

    timeline_response = client.get(f"/cases/{case_id}/timeline")
    assert timeline_response.status_code == 200
    events = timeline_response.json()["events"]
    assert any(event["source_artifact"].startswith("NTFS:$MFT:") for event in events)
    deleted_event = next(event for event in events if event["action"] == "deleted_record_seen")
    assert deleted_event["provenance"]["parser"] == "dfatool.mft"
    assert deleted_event["provenance"]["parser_name"] == "dfatool.mft"
    assert deleted_event["provenance"]["parser_version"]
    assert deleted_event["provenance"]["artifact_sha256"] == image_payload["sha256"]
    assert deleted_event["provenance"]["mft_entry_number"] == 3
    assert deleted_event["provenance"]["sequence_number"] == 9
    assert deleted_event["provenance"]["record_offset"] == 3072
    assert deleted_event["provenance"]["attribute_offset"] is not None
    assert deleted_event["attributes"]["path_confidence"] == "low"

    recommendations_response = client.get(f"/cases/{case_id}/recommendations")
    assert recommendations_response.status_code == 200
    assert deleted_event["id"] in recommendations_response.json()["recommendations"][0]["evidence_event_ids"]

    report_response = client.post(f"/cases/{case_id}/reports", json={"format": "markdown"})
    assert report_response.status_code == 200
    report_path = Path(report_response.json()["path"])
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Deleted file records need review" in report_text
    assert "NTFS:$MFT" in report_text


def test_sidecar_timeline_remains_fallback(tmp_path: Path) -> None:
    image = tmp_path / "sample.raw"
    image.write_bytes(b"sample ntfs image placeholder")
    sidecar = Path(f"{image}.timeline.json")
    sidecar.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "timestamp": "2026-06-12T00:00:00+00:00",
                        "source_artifact": "$MFT",
                        "record_id": "42-1",
                        "path": "/Users/Alice/Documents/deleted.txt",
                        "action": "deleted_record_seen",
                        "confidence": 0.82,
                        "provenance": {"attribute": "$FILE_NAME"},
                        "attributes": {"is_deleted": True},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    client = TestClient(create_app(tmp_path / "fallback.sqlite3"))
    case_id = client.post("/cases", json={"name": "Fallback Case"}).json()["id"]
    image_payload = client.post(f"/cases/{case_id}/images", json={"path": str(image)}).json()

    analysis_response = client.post(f"/cases/{case_id}/analysis", json={"image_id": image_payload["id"]})
    assert analysis_response.status_code == 200
    assert analysis_response.json()["event_count"] == 1

    events = client.get(f"/cases/{case_id}/timeline").json()["events"]
    assert events[0]["provenance"]["parser"] == "sidecar"
