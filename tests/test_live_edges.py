"""Recovery and concurrency cases at the live collection boundaries."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection

from sauron_sentinel import live
from sauron_sentinel.live import DashboardServer, EventStore, LiveMonitor
from sauron_sentinel.models import normalize
from sauron_sentinel.windows import CHANNELS, CollectionBatch


def _event(number=1):
    return normalize(
        {
            "schema_version": 1,
            "timestamp": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            "source": "windows-eventlog",
            "kind": "service.installed",
            "device_id": "windows-test",
            "synthetic": False,
            "attributes": {"record_id": number, "service_name": "Test service"},
        }
    )


def _sources(status="ok"):
    return [
        {
            "channel": channel,
            "status": status,
            "event_count": 0,
            **({"error": "permission_denied"} if status == "unavailable" else {}),
        }
        for channel in CHANNELS
    ]


def test_restart_recovers_committed_observation_missing_alert(tmp_path):
    # Simulate a stop between the committed event write and its derived alert.
    event = _event()
    store = EventStore(tmp_path)
    store.add_events([event])
    store.close()
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([event], _sources()))
    try:
        assert monitor.state()["summary"]["alerts_total"] == 1
        assert monitor.scan()
        assert monitor.state()["summary"]["alerts_total"] == 1
    finally:
        monitor.stop()
        store.close()
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([], _sources()))
    try:
        assert monitor.state()["summary"]["alerts_total"] == 1
    finally:
        monitor.stop()
        store.close()


def test_channel_failure_keeps_outage_query_window_for_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "_now", lambda: datetime(2026, 1, 2, tzinfo=UTC))
    calls = []
    sources = _sources()
    sources[1].update(status="unavailable", error="permission_denied")

    def collector(since, **kwargs):
        calls.append(since)
        return CollectionBatch([], sources if len(calls) == 1 else _sources())

    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=collector)
    try:
        assert monitor.scan()
        assert monitor.scan()
        assert calls[1] <= calls[0]
    finally:
        monitor.stop()
        store.close()


def test_batch_retention_snapshots_alert_evidence_before_pruning(tmp_path):
    events = [_event(1), _event(2)]
    store = EventStore(tmp_path, max_events=1)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch(events, _sources()))
    try:
        assert monitor.scan()
        state = monitor.state()
        assert state["summary"]["events_total"] == 1
        assert state["summary"]["alerts_total"] == 2
        assert {
            store.evidence(alert["alert_id"])["events"][0]["event_id"] for alert in state["alerts"]
        } == {event.event_id for event in events}
    finally:
        monitor.stop()
        store.close()


def test_failed_alert_write_recovers_from_committed_event_on_next_scan(tmp_path, monkeypatch):
    event = _event()
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([event], _sources()))
    add_alert = store.add_alert
    failed = False

    def fail_once(alert):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("private database diagnostic")
        add_alert(alert)

    monkeypatch.setattr(store, "add_alert", fail_once)
    try:
        assert not monitor.scan()
        assert monitor.state()["summary"]["events_total"] == 1
        assert monitor.state()["summary"]["alerts_total"] == 0
        assert "private database diagnostic" not in json.dumps(monitor.state())
        assert monitor.scan()
        state = monitor.state()
        assert state["monitor"]["last_error"] is None
        assert state["summary"]["alerts_total"] == 1
        alert = state["alerts"][0]
        assert store.evidence(alert["alert_id"])["events"][0]["event_id"] == event.event_id
    finally:
        monitor.stop()
        store.close()


def test_all_sources_unavailable_remain_visible_without_fabricated_events(tmp_path):
    store = EventStore(tmp_path)
    monitor = LiveMonitor(
        store, collector=lambda *a, **k: CollectionBatch([], _sources("unavailable"))
    )
    try:
        monitor.scan()
        state = monitor.state()
        assert state["summary"]["events_total"] == 0
        assert state["summary"]["alerts_total"] == 0
        assert len(state["sources"]) == 3
        assert all(source["status"] == "unavailable" for source in state["sources"])
    finally:
        monitor.stop()
        store.close()


def test_stop_waits_for_inflight_manual_scan_before_database_close(tmp_path):
    entered, release, stopping, stopped = (threading.Event() for _ in range(4))

    def collector(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return CollectionBatch([_event()], _sources())

    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=collector)

    def stop():
        stopping.set()
        monitor.stop()
        stopped.set()

    try:
        assert monitor.request_scan()
        assert entered.wait(3)
        stopper = threading.Thread(target=stop)
        stopper.start()
        assert stopping.wait(3)
        assert not stopped.wait(0.05)
        release.set()
        assert stopped.wait(3)
        stopper.join(3)
        assert not monitor.request_scan()
        assert not monitor.scan()
        assert store.snapshot()["summary"]["events_total"] == 1
    finally:
        release.set()
        monitor.stop()
        store.close()


def test_non_ascii_scan_token_rejected_with_response(tmp_path):
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([], _sources()))
    server = DashboardServer(monitor, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.request("POST", "/api/scan", headers={"X-Sentinel-Token": "\u00e9"})
        response = client.getresponse()
        assert response.status == 403
        assert json.loads(response.read()) == {"error": "token_required"}
        assert response.getheader("Cache-Control") == "no-store"
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        monitor.stop()
        store.close()
