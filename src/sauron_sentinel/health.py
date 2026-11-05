"""Describe collection visibility, never the security of the computer.

Health is computed from the latest monitor state; no Windows query or persisted
health history is created here. A successful empty query proves read access only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .windows import CHANNELS


def build_health(
    sources: Sequence[Mapping[str, Any]],
    monitor: Mapping[str, Any],
    last_scan_at: str | None,
) -> dict[str, Any]:
    """Summarize the configured channels and freshness of their last results.

    Source counters describe reported results even after a failed attempt; the
    explicit freshness flag prevents those old counts being a current assurance.
    ``ready`` means all queries completed without a cap, not complete auditing.
    Missing channel results stay pending and are never invented as successes.
    """
    reported = {source.get("channel"): source for source in sources}
    counts = {"ok": 0, "unavailable": 0, "error": 0, "pending": 0}
    limited = 0
    for channel in CHANNELS:
        source = reported.get(channel, {})
        status = source.get("status")
        counts[status if status in counts else "pending"] += 1
        limited += source.get("limit_reached") is True

    error = monitor.get("last_error")
    stopped = monitor.get("stopped") is True
    if stopped:
        status = "stopped"
    elif error:
        status = "error"
    elif last_scan_at is None:
        status = "starting"
    elif counts["ok"] == len(CHANNELS) and not limited:
        status = "ready"
    elif counts["ok"]:
        status = "partial"
    elif counts["error"]:
        status = "error"
    else:
        status = "unavailable"

    return {
        "status": status,
        "sources_total": len(CHANNELS),
        "sources_reported": sum(channel in reported for channel in CHANNELS),
        "sources_ok": counts["ok"],
        "sources_unavailable": counts["unavailable"],
        "sources_error": counts["error"],
        "sources_pending": counts["pending"],
        "sources_limited": limited,
        "source_results_current": last_scan_at is not None and not error and not stopped,
        "last_attempt_at": monitor.get("last_attempt_at"),
        "last_scan_at": last_scan_at,
        "last_error": error,
        "last_success_scope": "current_session",
    }
