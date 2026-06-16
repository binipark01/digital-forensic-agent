from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app.main import create_app
from app.services.timeline_adapters import DfatoolMftAdapter
from tests.fixtures_mft import synthetic_mft_bytes


def test_ntfs_mft_artifact_runs_internal_parser_without_not_implemented_warning(
    tmp_path: Path,
) -> None:
    evidence_root = make_evidence_root(tmp_path, synthetic_mft_bytes())
    client = TestClient(create_app(tmp_path / "ntfs-mft-artifact.sqlite3"))
    case_id = create_case(client)
    source_id = register_source(client, case_id, evidence_root)
    plan_id = create_plan(client, case_id, source_id)
    execute_plan(client, case_id, plan_id)
    artifacts = list_artifacts(client, case_id)
    mft_artifact = by_type(artifacts, "ntfs_mft")

    response = client.post(
        f"/cases/{case_id}/analysis",
        json={"artifact_ids": [mft_artifact["id"]], "parser_mode": "auto"},
    )

    assert_status(response, 200)
    analysis = response.json()
    assert analysis["status"] == "completed"
    assert analysis["event_count"] > 0
    assert "dfatool.mft" in analysis["tool_versions"]["selected_parsers"]
    assert not any(
        warning["code"] == "parser_not_implemented"
        and warning["artifact_id"] == mft_artifact["id"]
        for warning in analysis["warnings"]
    )

    events = client.get(f"/cases/{case_id}/timeline").json()["events"]
    created = next(
        event
        for event in events
        if event["record_id"] == "2-7"
        and event["action"] == "file_created"
        and event["source_artifact"] == "NTFS:$MFT:$STANDARD_INFORMATION"
    )
    assert created["artifact_id"] == mft_artifact["id"]
    assert created["provenance"]["artifact_id"] == mft_artifact["id"]
    assert created["provenance"]["artifact_sha256"] == mft_artifact["sha256"]
    assert created["provenance"]["parser_name"] == "dfatool.mft"
    assert created["provenance"]["parser_version"]
    assert created["provenance"]["mft_entry_number"] == 2
    assert created["provenance"]["sequence_number"] == 7
    assert created["provenance"]["record_offset"] == 2048
    assert created["provenance"]["timestamp_source"] == "$STANDARD_INFORMATION"
    assert created["attributes"]["file_name"] == "report.txt"
    assert created["attributes"]["parent_reference"]["entry"] == 1
    assert created["attributes"]["is_deleted"] is False
    assert created["attributes"]["is_directory"] is False


def test_malformed_ntfs_mft_artifact_completes_with_parser_warning(tmp_path: Path) -> None:
    payload = bytearray(synthetic_mft_bytes())
    payload[1024:1028] = b"BAAD"
    evidence_root = make_evidence_root(tmp_path, bytes(payload))
    client = TestClient(create_app(tmp_path / "ntfs-mft-warning.sqlite3"))
    case_id = create_case(client)
    source_id = register_source(client, case_id, evidence_root)
    plan_id = create_plan(client, case_id, source_id)
    execute_plan(client, case_id, plan_id)
    artifacts = list_artifacts(client, case_id)
    mft_artifact = by_type(artifacts, "ntfs_mft")

    response = client.post(
        f"/cases/{case_id}/analysis",
        json={"artifact_ids": [mft_artifact["id"]], "parser_mode": "auto"},
    )

    assert_status(response, 200)
    analysis = response.json()
    assert analysis["status"] == "completed_with_warnings"
    assert analysis["event_count"] > 0
    assert any(
        warning["code"] == "parser_warning"
        and warning["artifact_id"] == mft_artifact["id"]
        and "invalid FILE signature" in warning["message"]
        for warning in analysis["warnings"]
    )


def test_ntfs_mft_artifact_hash_mismatch_refuses_stale_provenance(tmp_path: Path) -> None:
    evidence_root = make_evidence_root(tmp_path, synthetic_mft_bytes())
    client = TestClient(create_app(tmp_path / "ntfs-mft-hash-mismatch.sqlite3"))
    case_id = create_case(client)
    source_id = register_source(client, case_id, evidence_root)
    plan_id = create_plan(client, case_id, source_id)
    execute_plan(client, case_id, plan_id)
    mft_artifact = by_type(list_artifacts(client, case_id), "ntfs_mft")
    (evidence_root / "$MFT").write_bytes(b"FILE" + (b"\x00" * 2044))

    response = client.post(
        f"/cases/{case_id}/analysis",
        json={"artifact_ids": [mft_artifact["id"]], "parser_mode": "auto"},
    )

    assert_status(response, 200)
    analysis = response.json()
    assert analysis["status"] == "completed_with_warnings"
    assert analysis["event_count"] == 0
    assert any(
        warning["code"] == "parser_warning"
        and warning["artifact_id"] == mft_artifact["id"]
        and "changed since registration" in warning["message"]
        for warning in analysis["warnings"]
    )


def test_mft_adapter_sanitizes_parser_failure_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mft_path = tmp_path / "$MFT"
    mft_path.write_bytes(synthetic_mft_bytes())

    def fail_parse(*args, **kwargs):
        raise OSError(f"sensitive path leaked: {mft_path}")

    monkeypatch.setattr("app.services.timeline_adapters.parse_mft_file", fail_parse)

    result = DfatoolMftAdapter().run({"path": str(mft_path)})

    assert result.events == []
    assert result.warning == "dfatool MFT parser failed before producing events (OSError)."
    assert str(mft_path) not in result.warning


def test_mixed_artifact_analysis_keeps_unsupported_parser_skip(tmp_path: Path) -> None:
    evidence_root = make_evidence_root(tmp_path, synthetic_mft_bytes())
    logfile = evidence_root / "$LogFile"
    logfile.write_bytes(b"unsupported logfile bytes")
    client = TestClient(create_app(tmp_path / "mixed-artifact.sqlite3"))
    case_id = create_case(client)
    source_id = register_source(client, case_id, evidence_root)
    plan_response = client.post(
        f"/cases/{case_id}/collection-plans",
        json={
            "name": "Mixed parser plan",
            "evidence_source_id": source_id,
            "targets": [
                {"artifact_type": "ntfs_mft", "relative_path": "$MFT"},
                {"artifact_type": "NTFS:$LogFile", "relative_path": "$LogFile"},
            ],
        },
    )
    assert_status(plan_response, 200)
    execute_plan(client, case_id, plan_response.json()["id"])
    artifacts = list_artifacts(client, case_id)
    mft_artifact = by_type(artifacts, "ntfs_mft")
    logfile_artifact = by_type(artifacts, "NTFS:$LogFile")

    response = client.post(
        f"/cases/{case_id}/analysis",
        json={
            "artifact_ids": [mft_artifact["id"], logfile_artifact["id"]],
            "parser_mode": "auto",
        },
    )

    assert_status(response, 200)
    analysis = response.json()
    assert analysis["status"] == "completed_with_warnings"
    assert analysis["event_count"] > 0
    assert any(
        warning["code"] == "parser_not_implemented"
        and warning["artifact_id"] == logfile_artifact["id"]
        for warning in analysis["warnings"]
    )
    assert not any(
        warning["code"] == "parser_not_implemented"
        and warning["artifact_id"] == mft_artifact["id"]
        for warning in analysis["warnings"]
    )


def create_case(client: TestClient) -> str:
    response = client.post("/cases", json={"name": "MFT Artifact Case", "examiner": "Analyst"})
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
            "name": "MFT parser plan",
            "evidence_source_id": source_id,
            "targets": [{"artifact_type": "ntfs_mft", "relative_path": "$MFT"}],
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


def make_evidence_root(tmp_path: Path, mft_bytes: bytes) -> Path:
    evidence_root = tmp_path / "fake_windows_evidence" / "C"
    evidence_root.mkdir(parents=True)
    (evidence_root / "$MFT").write_bytes(mft_bytes)
    (evidence_root / "Users").mkdir()
    (evidence_root / "Users" / "side.timeline.json").write_text(
        json.dumps({"events": []}),
        encoding="utf-8",
    )
    return evidence_root


def by_type(artifacts: list[dict[str, object]], artifact_type: str) -> dict[str, object]:
    return next(artifact for artifact in artifacts if artifact["artifact_type"] == artifact_type)


def assert_status(response: Response, status_code: int) -> None:
    assert response.status_code == status_code, response.text
