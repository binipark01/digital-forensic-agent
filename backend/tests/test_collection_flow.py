from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.collection_flow_helpers import (
    LOGFILE_RELATIVE_PATH,
    MFT_RELATIVE_PATH,
    MISSING_RELATIVE_PATH,
    SIDECAR_RELATIVE_PATH,
    USN_RELATIVE_PATH,
    artifacts_by_artifact_type,
    assert_status,
    collection_plan_payload,
    create_case,
    create_collection_plan,
    execute_collection_plan,
    make_fake_windows_evidence,
    path_for,
    register_evidence_source,
    sha256_file,
    source_fingerprint,
    targets_by_relative_path,
)


def test_registers_evidence_source_for_read_only_windows_directory(tmp_path: Path) -> None:
    # Given: a fake mounted Windows evidence directory under pytest's temp tree.
    evidence_root = make_fake_windows_evidence(tmp_path)
    client = TestClient(create_app(tmp_path / "source-registration.sqlite3"))
    case_id = create_case(client)

    # When: the analyst registers the directory as an evidence source.
    response = client.post(
        f"/cases/{case_id}/evidence-sources",
        json={
            "name": "Mounted Windows evidence",
            "source_type": "mounted_windows_directory",
            "root_path": str(evidence_root),
        },
    )

    # Then: the source is registered by reference, preserving the evidence path.
    assert_status(response, 200)
    payload = response.json()
    assert payload["case_id"] == case_id
    assert payload["name"] == "Mounted Windows evidence"
    assert payload["source_type"] == "mounted_windows_directory"
    assert payload["root_path"] == str(evidence_root.resolve())
    assert payload["id"]
    assert payload["registered_at"]


def test_collection_plan_classifies_targets_as_found_or_missing(tmp_path: Path) -> None:
    # Given: a registered source with four present targets and one absent target.
    evidence_root = make_fake_windows_evidence(tmp_path)
    client = TestClient(create_app(tmp_path / "plan-classification.sqlite3"))
    case_id = create_case(client)
    source_id = register_evidence_source(client, case_id, evidence_root)

    # When: the analyst creates a collection plan from relative Windows artifact targets.
    response = client.post(
        f"/cases/{case_id}/collection-plans",
        json=collection_plan_payload(source_id),
    )

    # Then: each target is classified without mutating the source directory.
    assert_status(response, 200)
    payload = response.json()
    targets = targets_by_relative_path(payload["targets"])
    assert targets[MFT_RELATIVE_PATH]["classification"] == "found"
    assert targets[USN_RELATIVE_PATH]["classification"] == "found"
    assert targets[USN_RELATIVE_PATH]["parser_hint"]["parser"] == "dfatool.usn"
    assert targets[USN_RELATIVE_PATH]["parser_hint"]["parser_status"] == "implemented"
    assert targets[SIDECAR_RELATIVE_PATH]["classification"] == "found"
    assert targets[LOGFILE_RELATIVE_PATH]["classification"] == "found"
    assert targets[MISSING_RELATIVE_PATH]["classification"] == "missing"
    assert targets[MISSING_RELATIVE_PATH]["resolved_path"] is None
    assert targets[MFT_RELATIVE_PATH]["resolved_path"] == str(path_for(evidence_root, MFT_RELATIVE_PATH).resolve())


def test_plan_execution_registers_evidence_artifacts_with_streaming_hashes_without_changing_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a classified plan and source files whose bytes must stay untouched.
    evidence_root = make_fake_windows_evidence(tmp_path)
    source_paths = [
        path_for(evidence_root, MFT_RELATIVE_PATH),
        path_for(evidence_root, USN_RELATIVE_PATH),
        path_for(evidence_root, SIDECAR_RELATIVE_PATH),
        path_for(evidence_root, LOGFILE_RELATIVE_PATH),
    ]
    original_fingerprints = {source_path: source_fingerprint(source_path) for source_path in source_paths}
    client = TestClient(create_app(tmp_path / "plan-execution.sqlite3"))
    case_id = create_case(client)
    source_id = register_evidence_source(client, case_id, evidence_root)
    plan_id = create_collection_plan(client, case_id, source_id)

    def fail_read_bytes(self: Path) -> bytes:
        raise AssertionError(f"hashing must stream {self}")

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    # When: the plan is executed.
    response = client.post(f"/cases/{case_id}/collection-plans/{plan_id}/execute")

    # Then: found targets become EvidenceArtifacts with hashes, and source files are unchanged.
    assert_status(response, 200)
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["registered_artifact_count"] == 4
    artifacts_response = client.get(f"/cases/{case_id}/evidence-artifacts")
    assert_status(artifacts_response, 200)
    artifacts = artifacts_response.json()["artifacts"]
    artifacts_by_type = artifacts_by_artifact_type(artifacts)
    assert artifacts_by_type["ntfs_mft"]["path"] == str(path_for(evidence_root, MFT_RELATIVE_PATH).resolve())
    assert artifacts_by_type["ntfs_mft"]["sha256"] == sha256_file(path_for(evidence_root, MFT_RELATIVE_PATH))
    assert artifacts_by_type["ntfs_usnjrnl"]["path"] == str(path_for(evidence_root, USN_RELATIVE_PATH).resolve())
    assert artifacts_by_type["ntfs_usnjrnl"]["sha256"] == sha256_file(path_for(evidence_root, USN_RELATIVE_PATH))
    assert artifacts_by_type["sidecar_timeline"]["path"] == str(path_for(evidence_root, SIDECAR_RELATIVE_PATH).resolve())
    assert artifacts_by_type["sidecar_timeline"]["sha256"] == sha256_file(path_for(evidence_root, SIDECAR_RELATIVE_PATH))
    assert artifacts_by_type["NTFS:$LogFile"]["path"] == str(path_for(evidence_root, LOGFILE_RELATIVE_PATH).resolve())
    assert artifacts_by_type["NTFS:$LogFile"]["sha256"] == sha256_file(path_for(evidence_root, LOGFILE_RELATIVE_PATH))
    for source_path, fingerprint in original_fingerprints.items():
        assert source_path.exists()
        assert source_fingerprint(source_path) == fingerprint


def test_analysis_skips_unsupported_artifacts_with_parser_not_implemented_warning(tmp_path: Path) -> None:
    # Given: an executed plan containing a found but unsupported NTFS:$LogFile artifact.
    evidence_root = make_fake_windows_evidence(tmp_path)
    client = TestClient(create_app(tmp_path / "unsupported-analysis.sqlite3"))
    case_id = create_case(client)
    source_id = register_evidence_source(client, case_id, evidence_root)
    plan_id = create_collection_plan(client, case_id, source_id)
    execute_collection_plan(client, case_id, plan_id)
    artifacts = client.get(f"/cases/{case_id}/evidence-artifacts").json()["artifacts"]
    logfile_artifact = artifacts_by_artifact_type(artifacts)["NTFS:$LogFile"]

    # When: analysis is requested for the unsupported artifact.
    response = client.post(
        f"/cases/{case_id}/analysis",
        json={"artifact_ids": [logfile_artifact["id"]], "parser_mode": "auto"},
    )

    # Then: the run completes with a parser_not_implemented warning and no fabricated events.
    assert_status(response, 200)
    payload = response.json()
    assert payload["status"] == "completed_with_warnings"
    assert payload["event_count"] == 0
    assert any(
        warning["code"] == "parser_not_implemented"
        and warning["artifact_id"] == logfile_artifact["id"]
        and warning["artifact_type"] == "NTFS:$LogFile"
        for warning in payload["warnings"]
    )


def test_sidecar_timeline_artifact_generates_timeline_events(tmp_path: Path) -> None:
    # Given: a sidecar .timeline.json file registered as an EvidenceArtifact path.
    evidence_root = make_fake_windows_evidence(tmp_path)
    sidecar_path = path_for(evidence_root, SIDECAR_RELATIVE_PATH)
    client = TestClient(create_app(tmp_path / "sidecar-artifact-analysis.sqlite3"))
    case_id = create_case(client)
    source_id = register_evidence_source(client, case_id, evidence_root)
    plan_id = create_collection_plan(client, case_id, source_id)
    execute_collection_plan(client, case_id, plan_id)
    artifacts = client.get(f"/cases/{case_id}/evidence-artifacts").json()["artifacts"]
    sidecar_artifact = artifacts_by_artifact_type(artifacts)["sidecar_timeline"]
    assert sidecar_artifact["path"] == str(sidecar_path.resolve())

    # When: analysis is requested for that sidecar artifact.
    response = client.post(
        f"/cases/{case_id}/analysis",
        json={"artifact_ids": [sidecar_artifact["id"]], "parser_mode": "auto"},
    )

    # Then: its events are persisted to the case timeline with artifact provenance.
    assert_status(response, 200)
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["event_count"] == 1
    timeline_response = client.get(f"/cases/{case_id}/timeline")
    assert_status(timeline_response, 200)
    events = timeline_response.json()["events"]
    assert len(events) == 1
    assert events[0]["source_artifact"] == "NTFS:$MFT"
    assert events[0]["action"] == "deleted_record_seen"
    assert events[0]["path"] == "/Users/Alice/Documents/deleted.txt"
    assert events[0]["provenance"]["parser"] == "sidecar"
    assert events[0]["provenance"]["artifact_id"] == sidecar_artifact["id"]
    assert events[0]["provenance"]["source_path"] == str(sidecar_path.resolve())


def test_analysis_uses_artifact_registry_when_no_artifact_ids_are_supplied(tmp_path: Path) -> None:
    evidence_root = make_fake_windows_evidence(tmp_path)
    client = TestClient(create_app(tmp_path / "registry-priority-analysis.sqlite3"))
    case_id = create_case(client)
    source_id = register_evidence_source(client, case_id, evidence_root)
    plan_id = create_collection_plan(client, case_id, source_id)
    execute_collection_plan(client, case_id, plan_id)

    response = client.post(f"/cases/{case_id}/analysis", json={"parser_mode": "auto"})

    assert_status(response, 200)
    payload = response.json()
    assert payload["status"] == "completed_with_warnings"
    assert payload["image_id"] is None
    assert payload["event_count"] >= 1
    assert any(warning["code"] == "parser_not_implemented" for warning in payload["warnings"])


def test_empty_analysis_completes_with_warning_when_nothing_is_processable(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path / "empty-analysis.sqlite3"))
    case_id = create_case(client)

    response = client.post(f"/cases/{case_id}/analysis", json={"parser_mode": "auto"})

    assert_status(response, 200)
    payload = response.json()
    assert payload["status"] == "completed_with_warnings"
    assert payload["event_count"] == 0
    assert payload["warnings"] == [
        {
            "code": "no_processable_evidence",
            "message": "No evidence artifacts, sidecar timeline artifact, or image fallback were available for analysis.",
        }
    ]
