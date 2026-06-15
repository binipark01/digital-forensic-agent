# Forensic Handling Guide

## Evidence handling rules

- Treat registered image paths as read-only.
- Calculate hashes before analysis.
- Keep original evidence outside `backend/data/`; the app stores metadata and reports only.
- Record parser capability and selected parser for every analysis run.
- Do not include unsupported AI conclusions in a report.

## Current parser behavior

The analyzer supports three paths:

1. First-party `dfatool.mft` parsing when the registered input is an extracted NTFS `$MFT` file.
2. Sidecar timeline files named `<image>.timeline.json`, `<image>.timeline.csv`, `<stem>.timeline.json`, or `<stem>.timeline.csv` as fallback.
3. A completed-with-warnings run when no parser can run.

Sidecar files are intended for regression tests, known-good examples, and controlled labs. They are not a substitute for original evidence provenance unless the sidecar itself is part of the case record.

Sleuth Kit CLI traversal is retained only for explicit validation/comparison runs. Normal v1 analysis should not depend on external forensic CLIs.

## Report standards

Reports must include:

- Case ID.
- Examiner.
- Event count.
- Evidence event IDs behind recommendations.
- Timeline sample or exported full timeline.
- Parser and provenance fields in CSV/JSON exports.
- For MFT events, artifact hash, MFT entry, sequence number, record offset, and attribute offset.

## Known v1 limits

- BitLocker images are unsupported unless already decrypted or mounted into a readable image.
- Native `$LogFile`, `$UsnJrnl:$J`, and Recycle Bin parsing is not implemented beyond what future first-party parsers emit.
- Full E01/raw image filesystem traversal into `$MFT` extraction is not implemented in v1; provide an extracted `$MFT` file.
- Large image analysis is synchronous in the API process; a durable queue should be added before multi-user or production use.
