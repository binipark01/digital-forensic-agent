from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from httpx import Response

from app.main import create_app
from app.services.timeline_adapters import DfatoolUsnAdapter
from tests.fixtures_usn import synthetic_usn_bytes

USN_RELATIVE_PATH = "$Extend/$UsnJrnl.J"


def test_ntfs_usnjrnl_artifact_runs_internal_parser_without_not_implemented_warning(
    tmp_path: Path,
) -> None:
    # Given: an extracted USN journal registered through the collection layer.
    evidence_root = make_evidence_root(tmp_path, synthetic_usn_bytes(include_malformed=True))
    client = TestClient(create_app(tmp_path / "ntfs-usn-artifact.sqlite3"))
    case_id = create_case(client)
    source_id = register_source(client, case_id, evidence_root)
    plan_id = create_plan(client, case_id, source_id)
    execute_plan(client, case_id, plan_id)
    usn_artifact = by_type(list_artifacts(client, case_id), "ntfs_usnjrnl")

    # When: analysis runs in auto mode.
    response = client.post(
        f"/cases/{case_id}/analysis",
        json={"artifact_ids": [usn_artifact["id"]], "parser_mode": "auto"},
    )

    # Then: dfatool.usn creates timeline events and records parser warnings.
    assert_status(response, 200)
    analysis = response.json()
    assert analysis["status"] == "completed_with_warnings"
    assert analysis["event_count"] > 0
    assert "dfatool.usn" in analysis["tool_versions"]["selected_parsers"]
    assert not any(
        warning["code"] == "parser_not_implemented"
        and warning["artifact_id"] == usn_artifact["id"]
        for warning in analysis["warnings"]
    )
    parser_run = analysis["tool_versions"]["parser_runs"][0]
    assert parser_run["parser_name"] == "dfatool.usn"
    assert parser_run["parser_version"]
    assert parser_run["status"] == "completed_with_warnings"
    assert parser_run["events_created"] > 0
    assert any("record length 8 is too small" in warning for warning in parser_run["warnings"])

    events_response = client.get(f"/cases/{case_id}/timeline")
    assert_status(events_response, 200)
    events = events_response.json()["events"]
    created = next(
        event
        for event in events
        if event["record_id"] == "100" and event["action"] == "file_created"
    )
    assert created["artifact_id"] == usn_artifact["id"]
    assert created["source_artifact"] == "NTFS:$UsnJrnl:$J"
    assert created["path"] == "created.txt"
    assert created["provenance"]["artifact_id"] == usn_artifact["id"]
    assert created["provenance"]["artifact_sha256"] == usn_artifact["sha256"]
    assert created["provenance"]["parser_name"] == "dfatool.usn"
    assert created["provenance"]["parser_version"]
    assert created["provenance"]["record_offset"] == 0
    assert created["provenance"]["usn"] == 100
    assert created["provenance"]["file_reference_number"] == 1970324836974634
    assert created["provenance"]["parent_file_reference_number"] == 281474976710661
    assert created["provenance"]["raw_reason"] == 0x100
    assert created["provenance"]["reason_flags"] == ["FILE_CREATE"]
    assert created["attributes"]["file_name"] == "created.txt"
    assert created["attributes"]["timestamp_source"] == "$UsnJrnl:$J"
    assert created["attributes"]["path_confidence"] == "low"

    detail_response = client.get(f"/cases/{case_id}/events/{created['id']}")
    assert_status(detail_response, 200)
    detail = detail_response.json()
    assert detail["attributes"]["parser_warnings"] == []
    assert detail["provenance"]["timestamp_source"] == "$UsnJrnl:$J"

    for report_format in ("markdown", "json", "csv"):
        report_response = client.post(
            f"/cases/{case_id}/reports",
            json={"format": report_format},
        )
        assert_status(report_response, 200)
        report_path = Path(report_response.json()["path"])
        report_content = report_path.read_text(encoding="utf-8")
        assert "NTFS:$UsnJrnl:$J" in report_content
        assert "created.txt" in report_content


def test_usn_adapter_sanitizes_parser_failure_messages(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # Given: a valid-looking USN journal whose parser raises an OS error.
    usn_path = tmp_path / "$UsnJrnl_J"
    usn_path.write_bytes(synthetic_usn_bytes())

    def fail_parse(*args, **kwargs):
        raise OSError(f"sensitive path leaked: {usn_path}")

    monkeypatch.setattr("app.services.timeline_adapters.parse_usn_file", fail_parse)

    # When: the adapter handles the parser failure.
    result = DfatoolUsnAdapter().run({"path": str(usn_path)})

    # Then: no sensitive path is exposed in the warning.
    assert result.events == []
    assert result.warning == "dfatool USN parser failed before producing events (OSError)."
    assert str(usn_path) not in result.warning


def create_case(client: TestClient) -> str:
    response = client.post("/cases", json={"name": "USN Artifact Case", "examiner": "Analyst"})
    assert_status(response, 200)
    return response.json()["id"]


def register_source(client: TestClient, case_id: str, evidence_root: Path) -> str:
    response = client.post(
        f"/cases/{case_id}/evidence-sources",
        json={
            "name": "Mounted Windows evidence",
            "source_type": "mounted_windows_directory",
            "root_path": str(evidence_root),
        },
    )
    assert_status(response, 200)
    return response.json()["id"]


def create_plan(client: TestClient, case_id: str, source_id: str) -> str:
    response = client.post(
        f"/cases/{case_id}/collection-plans",
        json={
            "name": "USN parser plan",
            "evidence_source_id": source_id,
            "targets": [{"artifact_type": "ntfs_usnjrnl", "relative_path": USN_RELATIVE_PATH}],
        },
    )
    assert_status(response, 200)
    return response.json()["id"]


def execute_plan(client: TestClient, case_id: str, plan_id: str) -> None:
    response = client.post(f"/cases/{case_id}/collection-plans/{plan_id}/execute")
    assert_status(response, 200)


def list_artifacts(client: TestClient, case_id: str) -> list[dict[str, object]]:
    response = client.get(f"/cases/{case_id}/evidence-artifacts")
    assert_status(response, 200)
    return response.json()["artifacts"]


def make_evidence_root(tmp_path: Path, usn_bytes: bytes) -> Path:
    evidence_root = tmp_path / "fake_windows_evidence" / "C"
    usn_path = evidence_root.joinpath(*USN_RELATIVE_PATH.split("/"))
    usn_path.parent.mkdir(parents=True)
    usn_path.write_bytes(usn_bytes)
    return evidence_root


def by_type(artifacts: list[dict[str, object]], artifact_type: str) -> dict[str, object]:
    return next(artifact for artifact in artifacts if artifact["artifact_type"] == artifact_type)


def assert_status(response: Response, status_code: int) -> None:
    assert response.status_code == status_code, response.text
