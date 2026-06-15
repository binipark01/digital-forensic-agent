from __future__ import annotations

from collections import Counter
from typing import Any


def build_recommendations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []

    deleted = [
        event
        for event in events
        if "deleted" in event["action"] or event.get("attributes", {}).get("is_deleted")
    ]
    if deleted:
        recommendations.append(
            {
                "title": "Deleted file records need review",
                "rationale": (
                    f"{len(deleted)} timeline events indicate deleted records or deleted directory "
                    "entries. Review parent paths and correlate with Recycle Bin artifacts before "
                    "treating them as intentional deletion."
                ),
                "evidence_event_ids": [event["id"] for event in deleted[:12]],
                "next_steps": [
                    "Filter the timeline to deleted_record_seen actions.",
                    "Compare $FILE_NAME parent references with Recycle Bin entries.",
                    "Export the matching events into the report appendix.",
                ],
            }
        )

    sources = Counter(event["source_artifact"] for event in events)
    if sources:
        top_source, count = sources.most_common(1)[0]
        recommendations.append(
            {
                "title": f"Primary evidence source is {top_source}",
                "rationale": (
                    f"{count} events came from {top_source}. Treat conclusions as strongest where "
                    "they can be corroborated by a second artifact source."
                ),
                "evidence_event_ids": [
                    event["id"] for event in events if event["source_artifact"] == top_source
                ][:12],
                "next_steps": [
                    "Check whether $UsnJrnl:$J or Recycle Bin evidence exists for the same paths.",
                    "Keep parser and source-artifact names in the final report.",
                ],
            }
        )

    low_confidence = [event for event in events if float(event["confidence"]) < 0.8]
    if low_confidence:
        recommendations.append(
            {
                "title": "Low-confidence events should stay out of conclusions",
                "rationale": (
                    f"{len(low_confidence)} events have confidence below 0.80. They are useful "
                    "investigative leads but should not be phrased as findings without corroboration."
                ),
                "evidence_event_ids": [event["id"] for event in low_confidence[:12]],
                "next_steps": [
                    "Use low-confidence events as search pivots.",
                    "Require corroborating artifacts before report inclusion.",
                ],
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "title": "No forensic timeline events available yet",
                "rationale": (
                    "The case has no timeline evidence to summarize. Register an extracted NTFS "
                    "$MFT file for dfatool parsing, or provide a sidecar timeline for controlled "
                    "fallback testing."
                ),
                "evidence_event_ids": [],
                "next_steps": [
                    "Confirm the evidence path is reachable from the backend process.",
                    "If the input is a full disk image, extract `$MFT` read-only before v1 analysis.",
                    "Use Sleuth Kit only for explicit validation or comparison runs.",
                ],
            }
        )

    return recommendations
