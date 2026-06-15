# Digital Forensic Automation Agent

Local-first Windows NTFS triage tool for disk-image based file and deletion timelines.

## What v1 does

- Registers read-only `E01`, `Ex01`, `S01`, `dd`, `img`, and `raw` disk image paths.
- Calculates MD5, SHA1, and SHA256 before analysis.
- Stores cases, images, analysis runs, normalized timeline events, reports, and provenance in SQLite.
- Exposes a FastAPI backend and a React dashboard.
- Uses a parser adapter structure:
  - sidecar timeline files for reproducible tests and demos,
  - Sleuth Kit CLI (`mmls`, `fls`) when installed,
  - explicit limitation warnings when forensic parsers are unavailable.

## Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
uvicorn app.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

## Frontend

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Dashboard: http://127.0.0.1:5173

If the repository is inside a synced drive folder and `node_modules` extraction fails with `EBADF`, `EPERM`, or symlink errors, run the temp-mirror scripts instead:

```powershell
.\scripts\build-frontend-temp.ps1
.\scripts\start-frontend-temp.ps1
```

## Optional forensic tooling

Install The Sleuth Kit and ensure `mmls` and `fls` are on `PATH` for direct NTFS image traversal. The backend remains usable without these tools, but analysis runs will report the parser limitation and only ingest explicit sidecar timelines.

Sidecar demo format: create a file next to the image named `<image filename>.timeline.json` with:

```json
{
  "events": [
    {
      "timestamp": "2026-06-12T00:00:00+00:00",
      "source_artifact": "$MFT",
      "record_id": "42-1",
      "path": "/Users/Alice/Documents/deleted.txt",
      "action": "deleted_record_seen",
      "confidence": 0.82,
      "provenance": {"parser": "fixture", "attribute": "$FILE_NAME"}
    }
  ]
}
```
