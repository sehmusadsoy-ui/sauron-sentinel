"""Collection visibility uses controlled channel responses, never local logs."""

import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from sauron_sentinel import live
from sauron_sentinel.health import build_health
from sauron_sentinel.live import EventStore, LiveMonitor
from sauron_sentinel.models import format_timestamp
from sauron_sentinel.windows import CHANNELS, CollectionBatch

STAMP = "2026-01-02T12:00:00.000000Z"


def sources(*statuses, limited=False):
    return [
        {
            "channel": channel,
            "status": status,
            "event_count": 0,
            "limit_reached": limited and index == 0,
            **({"error": "permission_denied"} if status == "unavailable" else {}),
            **({"error": "timeout"} if status == "error" else {}),
        }
        for index, (channel, status) in enumerate(zip(CHANNELS, statuses, strict=False))
    ]


@pytest.mark.parametrize(
    "statuses,monitor,last_scan,limited,expected",
    [
        ((), {}, None, False, "starting"),
        ((), {"running": True, "scanning": True}, None, False, "starting"),
        (("ok", "ok", "ok"), {"running": True}, STAMP, False, "ready"),
        (("ok", "ok", "ok"), {"running": False}, STAMP, False, "ready"),
        (("ok", "ok", "ok"), {}, STAMP, True, "partial"),
        (("ok", "unavailable", "ok"), {}, STAMP, False, "partial"),
        (("ok", "error", "unavailable"), {}, STAMP, False, "partial"),
        (("ok",), {}, STAMP, False, "partial"),
        (("pending", "pending", "pending"), {}, STAMP, False, "unavailable"),
        (("unavailable", "unavailable", "unavailable"), {}, STAMP, False, "unavailable"),
        (("unavailable", "error", "unavailable"), {}, STAMP, False, "error"),
        (("error", "error", "error"), {}, STAMP, False, "error"),
        (("ok", "ok", "ok"), {"last_error": "collection_failed"}, STAMP, False, "error"),
        ((), {"last_error": "collection_failed"}, None, False, "error"),
        (("ok", "ok", "ok"), {"stopped": True}, STAMP, False, "stopped"),
        ((), {"stopped": True}, None, False, "stopped"),
    ],
)
def test_health_status_matrix(statuses, monitor, last_scan, limited, expected):
    result = build_health(sources(*statuses, limited=limited), monitor, last_scan)
    assert result["status"] == expected
    assert result["sources_total"] == 3
    assert result["sources_reported"] == len(statuses)
    assert result["sources_ok"] == statuses.count("ok")
    assert result["sources_unavailable"] == statuses.count("unavailable")
    assert result["sources_error"] == statuses.count("error")
    assert result["sources_pending"] == statuses.count("pending") + 3 - len(statuses)
    assert result["sources_limited"] == int(limited)
    assert result["source_results_current"] is bool(
        last_scan and not monitor.get("last_error") and not monitor.get("stopped")
    )


def test_health_contract_keeps_missing_channels_pending_and_inputs_unchanged():
    reported = sources("ok")
    reported.append({"channel": "Unexpected", "status": "ok", "event_count": 500})
    original = deepcopy(reported)
    result = build_health(reported, {"last_attempt_at": STAMP}, STAMP)
    assert result == {
        "status": "partial",
        "sources_total": 3,
        "sources_reported": 1,
        "sources_ok": 1,
        "sources_unavailable": 0,
        "sources_error": 0,
        "sources_pending": 2,
        "sources_limited": 0,
        "source_results_current": True,
        "last_attempt_at": STAMP,
        "last_scan_at": STAMP,
        "last_error": None,
        "last_success_scope": "current_session",
    }
    assert reported == original


def test_success_failure_and_recovery_preserve_only_real_session_success(tmp_path, monkeypatch):
    clock = [datetime(2026, 1, 2, 12, tzinfo=UTC)]
    monkeypatch.setattr(live, "_now", lambda: clock[0])
    store = EventStore(tmp_path)
    raw = sources("ok", "ok", "ok")
    monitor = LiveMonitor(store, collector=lambda *_a, **_k: CollectionBatch([], raw))
    try:
        assert monitor.state()["health"]["status"] == "starting"
        assert monitor.scan()
        first = monitor.state()
        first_time = format_timestamp(clock[0])
        assert first["health"]["status"] == "ready"
        assert [source["last_success_at"] for source in first["sources"]] == [first_time] * 3
        assert all("last_success_at" not in source for source in raw)
        assert first["summary"]["events_total"] == 0
        assert first["events"] == first["alerts"] == []

        clock[0] += timedelta(seconds=15)
        raw = sources("ok", "unavailable", "ok")
        assert monitor.scan()
        partial = monitor.state()
        partial_time = format_timestamp(clock[0])
        assert partial["health"]["status"] == "partial"
        assert [source["last_success_at"] for source in partial["sources"]] == [
            partial_time,
            first_time,
            partial_time,
        ]

        def fail(*_a, **_k):
            raise OSError("private filesystem detail must not escape")

        clock[0] += timedelta(seconds=15)
        monitor.collector = fail
        assert not monitor.scan()
        failed = monitor.state()
        assert failed["health"]["status"] == "error"
        assert failed["health"]["source_results_current"] is False
        assert failed["health"]["sources_ok"] == 2
        assert failed["sources"] == partial["sources"]
        assert failed["last_scan_at"] == partial["last_scan_at"]
        assert failed["health"]["last_attempt_at"] == format_timestamp(clock[0])
        assert failed["health"]["last_error"] == "collection_failed"
        assert "private" not in str(failed)

        clock[0] += timedelta(seconds=15)
        raw = sources("ok", "ok", "ok")
        monitor.collector = lambda *_a, **_k: CollectionBatch([], raw)
        assert monitor.scan()
        recovered = monitor.state()
        assert recovered["health"]["status"] == "ready"
        assert recovered["health"]["source_results_current"] is True
        assert recovered["health"]["last_error"] is None
        assert [source["last_success_at"] for source in recovered["sources"]] == [
            format_timestamp(clock[0])
        ] * 3
        assert recovered["summary"]["events_total"] == 0
        monitor.stop()
        assert monitor.state()["health"]["status"] == "stopped"
    finally:
        monitor.stop()
        store.close()

    # Event storage persists, but source query times are intentionally session-only.
    store = EventStore(tmp_path)
    monitor = LiveMonitor(
        store, collector=lambda *_a, **_k: CollectionBatch([], sources("unavailable"))
    )
    try:
        assert monitor.state()["sources"] == []
        assert monitor.scan()
        assert monitor.state()["sources"][0]["last_success_at"] is None
        assert monitor.state()["health"]["status"] == "unavailable"
    finally:
        monitor.stop()
        store.close()


def test_store_closes_connection_after_schema_failure_and_preserves_database(tmp_path, monkeypatch):
    original = b"Controlled invalid database fixture; no user records."
    database = tmp_path / "sentinel.db"
    database.write_bytes(original)
    connections = []
    connect = sqlite3.connect

    class RecordingConnection(sqlite3.Connection):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    def recording_connect(*args, **kwargs):
        connection = connect(*args, **kwargs, factory=RecordingConnection)
        connections.append(connection)
        return connection

    monkeypatch.setattr(live.sqlite3, "connect", recording_connect)
    with pytest.raises(sqlite3.DatabaseError):
        EventStore(tmp_path)
    assert len(connections) == 1 and connections[0].closed
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")
    assert database.read_bytes() == original


def test_initial_collection_exception_does_not_invent_access_or_success(tmp_path, monkeypatch):
    now = datetime(2026, 1, 2, 12, tzinfo=UTC)
    monkeypatch.setattr(live, "_now", lambda: now)

    def fail(*_a, **_k):
        raise RuntimeError("collector failure")

    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=fail)
    try:
        assert not monitor.scan()
        result = monitor.state()
        assert result["last_scan_at"] is None
        assert result["sources"] == []
        assert result["health"]["status"] == "error"
        assert result["health"]["sources_ok"] == 0
        assert result["health"]["sources_pending"] == 3
        assert result["health"]["source_results_current"] is False
        assert result["health"]["last_attempt_at"] == format_timestamp(now)
        assert result["summary"]["events_total"] == 0
    finally:
        monitor.stop()
        store.close()
