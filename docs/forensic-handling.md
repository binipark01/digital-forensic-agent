# Forensic Handling Guide

## Evidence handling rules

- Treat registered image paths as read-only.
- Calculate hashes before analysis.
- Keep original evidence outside `backend/data/`; the app stores metadata and reports only.
- Record parser capability and selected parser for every analysis run.
- Do not include unsupported AI conclusions in a report.

## Current parser behavior

The analyzer supports three paths:

1. Sidecar timeline files named `<image>.timeline.json`, `<image>.timeline.csv`, `<stem>.timeline.json`, or `<stem>.timeline.csv`.
2. Sleuth Kit CLI traversal with `fls`; `mmls` is used when available to find an NTFS/basic-data partition offset.
3. A completed-with-warnings run when no parser can run.

Sidecar files are intended for regression tests, known-good examples, and controlled labs. They are not a substitute for original evidence provenance unless the sidecar itself is part of the case record.

## Report standards

Reports must include:

- Case ID.
- Examiner.
- Event count.
- Evidence event IDs behind recommendations.
- Timeline sample or exported full timeline.
- Parser and provenance fields in CSV/JSON exports.

## Known v1 limits

- BitLocker images are unsupported unless already decrypted or mounted into a readable image.
- Native `$LogFile`, `$UsnJrnl:$J`, and Recycle Bin parsing is not implemented beyond what the active parser adapter emits.
- Large image analysis is synchronous in the API process; a durable queue should be added before multi-user or production use.

