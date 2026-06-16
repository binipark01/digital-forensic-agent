from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from fastapi.testclient import TestClient
from httpx import Response

from tests.fixtures_mft import synthetic_mft_bytes
from tests.fixtures_usn import synthetic_usn_bytes

MFT_RELATIVE_PATH = "$MFT"
USN_RELATIVE_PATH = "$Extend/$UsnJrnl.J"
LOGFILE_RELATIVE_PATH = "$LogFile"
SIDECAR_RELATIVE_PATH = "Users/Alice/AppData/Local/Timeline/deleted.timeline.json"
MISSING_RELATIVE_PATH = "$Recycle.Bin/S-1-5-21-1000/$I123456.txt"


def create_case(client: TestClient) -> str:
    response = client.post("/cases", json={"name": "Collection Case", "examiner": "Analyst"})
    assert_status(response, 200)
    return response.json()["id"]


def register_evidence_source(client: TestClient, case_id: str, evidence_root: Path) -> str:
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


def create_collection_plan(client: TestClient, case_id: str, source_id: str) -> str:
    response = client.post(f"/cases/{case_id}/collection-plans", json=collection_plan_payload(source_id))
    assert_status(response, 200)
    return response.json()["id"]


def execute_collection_plan(client: TestClient, case_id: str, plan_id: str) -> None:
    response = client.post(f"/cases/{case_id}/collection-plans/{plan_id}/execute")
    assert_status(response, 200)


def collection_plan_payload(source_id: str) -> dict[str, object]:
    return {
        "name": "NTFS triage plan",
        "evidence_source_id": source_id,
        "targets": [
            {"artifact_type": "ntfs_mft", "relative_path": MFT_RELATIVE_PATH},
            {"artifact_type": "ntfs_usnjrnl", "relative_path": USN_RELATIVE_PATH},
            {"artifact_type": "sidecar_timeline", "relative_path": SIDECAR_RELATIVE_PATH},
            {"artifact_type": "NTFS:$LogFile", "relative_path": LOGFILE_RELATIVE_PATH},
            {"artifact_type": "recycle_bin", "relative_path": MISSING_RELATIVE_PATH},
        ],
    }


def make_fake_windows_evidence(tmp_path: Path) -> Path:
    evidence_root = tmp_path / "fake_windows_evidence" / "C"
    evidence_root.mkdir(parents=True)
    path_for(evidence_root, MFT_RELATIVE_PATH).write_bytes(synthetic_mft_bytes())
    usn_path = path_for(evidence_root, USN_RELATIVE_PATH)
    usn_path.parent.mkdir(parents=True, exist_ok=True)
    usn_path.write_bytes(synthetic_usn_bytes())
    path_for(evidence_root, LOGFILE_RELATIVE_PATH).write_bytes(b"unsupported logfile bytes")
    sidecar = path_for(evidence_root, SIDECAR_RELATIVE_PATH)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(json.dumps({"events": [_sidecar_deleted_event()]}), encoding="utf-8-sig")
    return evidence_root


def path_for(root: Path, relative_path: str) -> Path:
    return root.joinpath(*relative_path.split("/"))


def targets_by_relative_path(targets: Iterable[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(target["relative_path"]): target for target in targets}


def artifacts_by_artifact_type(artifacts: Iterable[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(artifact["artifact_type"]): artifact for artifact in artifacts}


def source_fingerprint(path: Path) -> tuple[int, str]:
    return (path.stat().st_size, sha256_file(path))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_status(response: Response, status_code: int) -> None:
    assert response.status_code == status_code, response.text


def _sidecar_deleted_event() -> dict[str, object]:
    return {
        "timestamp": "2026-06-12T00:00:00+00:00",
        "source_artifact": "NTFS:$MFT",
        "record_id": "42-1",
        "path": "/Users/Alice/Documents/deleted.txt",
        "action": "deleted_record_seen",
        "confidence": 0.82,
        "provenance": {"attribute": "$FILE_NAME"},
        "attributes": {"is_deleted": True},
    }
