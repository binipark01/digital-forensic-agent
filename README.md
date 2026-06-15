# Digital Forensic Automation Agent

Local-first Windows NTFS triage tool for disk-image based file and deletion timelines.

## What v1 does

- Registers read-only `E01`, `Ex01`, `S01`, `dd`, `img`, and `raw` disk image paths.
- Calculates MD5, SHA1, and SHA256 before analysis.
- Stores cases, images, analysis runs, normalized timeline events, reports, and provenance in SQLite.
- Exposes a FastAPI backend and a React dashboard.
- Uses a parser adapter structure:
  - first-party `dfatool` library parsing for extracted NTFS `$MFT` files,
  - sidecar timeline files only as reproducible fallback fixtures,
  - Sleuth Kit CLI only for explicit validation/comparison runs.

## dfatool

`dfatool` is the repository's first-party forensic parser toolkit. The v1 parser reads extracted NTFS `$MFT` files directly and does not call AnalyzeMFT, MFTECmd, or Sleuth Kit for normal analysis.

```powershell
cd backend
python -m pip install -e .[dev]
dfatool mft parse --input 'C:\evidence\$MFT' --json out.jsonl --csv out.csv
dfatool mft timeline --input 'C:\evidence\$MFT' --output timeline.jsonl
dfatool mft dump-record --input 'C:\evidence\$MFT' --entry 12345
```

The parser emits `NTFS:$MFT` timeline events with artifact hash, MFT entry, sequence number, record offset, and attribute offset provenance.

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

## Validation tooling

Install The Sleuth Kit and ensure `mmls` and `fls` are on `PATH` only when you want comparison output. The default backend analysis path does not call external forensic CLIs.

Sidecar demo format: create a file next to the image named `<image filename>.timeline.json` with:

```json
{
  "events": [
    {
      "timestamp": "2026-06-12T00:00:00+00:00",
      "source_artifact": "NTFS:$MFT",
      "record_id": "42-1",
      "path": "/Users/Alice/Documents/deleted.txt",
      "action": "deleted_record_seen",
      "confidence": 0.82,
      "provenance": {"parser": "fixture", "attribute": "$FILE_NAME"}
    }
  ]
}
```
