# Architecture

## System shape

Digital Forensic Automation Agent v1 is a local-first web application:

- React dashboard for analyst workflow.
- FastAPI backend for cases, images, analysis runs, timeline events, recommendations, and reports.
- SQLite case database stored under `backend/data/` by default.
- Read-only disk image references; image bytes are hashed and never modified.

## Data flow

1. Analyst creates a case.
2. Analyst registers an absolute image path.
3. Backend validates the path, detects image format, calculates MD5/SHA1/SHA256, and stores parser hints.
4. Analyst starts analysis.
5. Analyzer chooses the first available normal-analysis adapter:
   - first-party `dfatool.mft` parsing when the input is an extracted NTFS `$MFT`,
   - sidecar timeline file as deterministic fallback for fixtures and demos,
   - explicit warning if no parser can run.
   Sleuth Kit CLI remains available only when explicitly requested for validation/comparison.
6. Events are normalized into the timeline schema.
7. UI filters events and shows event-level provenance.
8. Reports render Markdown, CSV, or JSON with recommendation evidence IDs.

## Normalized event contract

Every timeline event has:

- `timestamp`: ISO 8601 string or null.
- `source_artifact`: artifact family such as `NTFS:$MFT`.
- `record_id`: parser-level file reference, inode, or source record key.
- `path`: normalized evidence path.
- `action`: SI/FN separated timestamp actions such as `si_created` and `fn_modified`, deletion/ADS observations, or parser-specific actions.
- `confidence`: 0.0 to 1.0.
- `provenance`: parser, tool, image path, line/offset/attribute, and other reproducibility fields.
- `attributes`: non-contract parser details.

## Parser boundary

The app does not claim complete NTFS coverage unless a parser emits events. `dfatool.mft` directly parses MFT FILE records, USA fixups, `$STANDARD_INFORMATION`, `$FILE_NAME`, and `$DATA` metadata for v1. Full disk traversal, `$UsnJrnl:$J`, Recycle Bin, and encrypted images remain outside the completed first-party parser boundary.

## AI boundary

The recommendation layer is deterministic in v1. It groups deleted records, source-artifact dominance, and low-confidence events into analyst prompts. Future LLM output must preserve the same rule: no report sentence without linked evidence event IDs.
