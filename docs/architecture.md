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
5. Analyzer chooses the first available adapter:
   - sidecar timeline file for deterministic fixtures and demos,
   - Sleuth Kit CLI bodyfile traversal when `fls` is available,
   - explicit warning if no parser can run.
6. Events are normalized into the timeline schema.
7. UI filters events and shows event-level provenance.
8. Reports render Markdown, CSV, or JSON with recommendation evidence IDs.

## Normalized event contract

Every timeline event has:

- `timestamp`: ISO 8601 string or null.
- `source_artifact`: artifact family such as `$MFT`.
- `record_id`: parser-level file reference, inode, or source record key.
- `path`: normalized evidence path.
- `action`: observed, created, modified, accessed, metadata_changed, deleted_record_seen, or parser-specific action.
- `confidence`: 0.0 to 1.0.
- `provenance`: parser, tool, image path, line/offset/attribute, and other reproducibility fields.
- `attributes`: non-contract parser details.

## Parser boundary

The app does not claim complete NTFS coverage unless a parser emits events. Missing parser dependencies are reported in `analysis_runs.warning`. This is intentional: silent fallback would be unsafe for forensic use.

## AI boundary

The recommendation layer is deterministic in v1. It groups deleted records, source-artifact dominance, and low-confidence events into analyst prompts. Future LLM output must preserve the same rule: no report sentence without linked evidence event IDs.

