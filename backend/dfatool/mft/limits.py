from __future__ import annotations

from typing import Any

from dfatool.mft.models import MftParseResult


def append_limited_event(
    events: list[dict[str, Any]],
    event: dict[str, Any],
    result: MftParseResult,
    max_events: int,
) -> None:
    if len(events) < max_events:
        events.append(event)
        if len(events) == max_events:
            record_event_limit(result, max_events)
        return
    record_event_limit(result, max_events)


def record_event_limit(result: MftParseResult, max_events: int) -> None:
    if not any("timeline event limit reached" in warning for warning in result.warnings):
        result.warnings.append(f"timeline event limit reached at {max_events} events")
