"""Exercise real local HTTP boundaries, storage, and monitor recovery with fake logs."""

import json
import threading
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from types import SimpleNamespace

import pytest

from sauron_sentinel import live
from sauron_sentinel.engine import RuleEngine
from sauron_sentinel.live import DashboardServer, EventStore, LiveMonitor
from sauron_sentinel.models import ValidationError, normalize
from sauron_sentinel.rules import load_rules


def observation(number=0, *, kind="service.installed", synthetic=False):
    return normalize(
        {
            "schema_version": 1,
            "timestamp": (
                datetime.now(UTC) - timedelta(minutes=10) + timedelta(seconds=number)
            ).isoformat(),
            "source": "windows-eventlog",
            "kind": kind,
            "device_id": "windows-test",
            "synthetic": synthetic,
            "attributes": {"record_id": number, "user": "test-user"},
        }
    )


def batch(events):
    return SimpleNamespace(
        events=events, sources=[{"channel": "System", "status": "ok", "event_count": len(events)}]
    )


def test_store_deduplicates_persists_and_rejects_synthetic(tmp_path):
    event = observation()
    store = EventStore(tmp_path)
    assert store.add_events([event, event]) == [event]
    assert store.snapshot()["summary"]["events_24h"] == 1
    with pytest.raises(ValidationError):
        store.add_events([observation(1, synthetic=True)])
    store.close()
    reopened = EventStore(tmp_path)
    assert reopened.engine_events() == [event]
    reopened.close()


def test_retention_preserves_alert_evidence_snapshot(tmp_path):
    store = EventStore(tmp_path, max_events=1, max_alerts=1)
    engine = RuleEngine(load_rules())
    first = observation()
    store.add_events([first])
    alert = engine.process(first)[0]
    store.add_alert(alert)
    store.add_alert(alert)
    store.add_events([observation(1)])
    assert store.snapshot()["summary"] == {
        "events_total": 1,
        "events_24h": 1,
        "alerts_total": 1,
        "alerts_24h": 1,
    }
    assert store.evidence(alert.alert_id)["events"][0]["event_id"] == first.event_id
    next_event = observation(2)
    store.add_events([next_event])
    next_alert = engine.process(next_event)[0]
    store.add_alert(next_alert)
    assert store.evidence(alert.alert_id) is None
    assert store.evidence("missing") is None
    store.close()


@pytest.mark.parametrize("events,alerts", [(0, 1), (1, 0), (100001, 1), (1, 10001)])
def test_storage_limits(tmp_path, events, alerts):
    with pytest.raises(ValidationError):
        EventStore(tmp_path, events, alerts)


def test_monitor_scan_dedup_late_records_and_recovery(tmp_path):
    store = EventStore(tmp_path)
    current = observation(5)
    responses = iter([batch([current]), batch([current]), batch([observation(0)])])
    monitor = LiveMonitor(store, collector=lambda *_args, **_kw: next(responses))
    assert monitor.scan()
    assert monitor.scan()
    assert monitor.state()["summary"]["alerts_total"] == 1
    assert monitor.scan()
    state = monitor.state()
    assert state["summary"]["events_total"] == 2
    assert state["summary"]["alerts_total"] == 1
    assert state["monitor"]["late_events"] == 1
    assert state["last_scan_at"] and state["sources"][0]["status"] == "ok"

    def fail(*_args, **_kw):
        raise OSError("private local detail")

    monitor.collector = fail
    assert not monitor.scan()
    assert monitor.state()["monitor"]["last_error"] == "collection_failed"
    monitor.collector = lambda *_args, **_kw: batch([])
    assert monitor.scan()
    assert monitor.state()["monitor"]["last_error"] is None
    monitor.stop()
    store.close()


def test_monitor_rebuild_and_busy_scan(tmp_path):
    store = EventStore(tmp_path)
    event = observation()
    store.add_events([event])
    monitor = LiveMonitor(store, collector=lambda *_a, **_k: batch([]))
    assert monitor._watermark == event.timestamp
    monitor._scan_lock.acquire()
    assert not monitor.scan()
    monitor._scan_lock.release()
    with monitor._status_lock:
        monitor._status["scanning"] = True
    assert not monitor.request_scan()
    with monitor._status_lock:
        monitor._status["scanning"] = False
    assert monitor.request_scan()
    monitor.stop()
    store.close()


def test_monitor_background_start_stop(tmp_path):
    store = EventStore(tmp_path)
    called = threading.Event()

    def collect(*_a, **_k):
        called.set()
        return batch([])

    monitor = LiveMonitor(store, collector=collect)
    monitor.start()
    monitor.start()
    assert called.wait(3)
    monitor.stop()
    assert not monitor.state()["monitor"]["running"]
    store.close()


@pytest.mark.parametrize("interval,hours", [(4, 24), (3601, 24), (15, 0), (15, 169)])
def test_monitor_settings_validated(tmp_path, interval, hours):
    store = EventStore(tmp_path)
    with pytest.raises(ValidationError):
        LiveMonitor(store, interval, hours)
    store.close()


@pytest.fixture
def dashboard(tmp_path):
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *_a, **_k: batch([observation()]))
    monitor.scan()
    server = DashboardServer(monitor, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    monitor.stop()
    store.close()


def request(server, path="/api/state", *, method="GET", headers=None, body=None):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        client.close()


def test_dashboard_state_export_evidence(dashboard):
    status, headers, data = request(dashboard)
    state = json.loads(data)
    assert status == 200 and state["summary"]["events_total"] == 1
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    alert_id = state["alerts"][0]["alert_id"]
    status, _, data = request(dashboard, f"/api/alerts/{alert_id}/evidence")
    assert status == 200 and len(json.loads(data)["events"]) == 1
    status, headers, _ = request(dashboard, "/api/export")
    assert status == 200 and "attachment" in headers["Content-Disposition"]
    assert request(dashboard, "/api/alerts/" + "a" * 64 + "/evidence")[0] == 404


@pytest.mark.parametrize("path", ["/", "/index.html", "/app.js", "/styles.css"])
def test_dashboard_static_files(dashboard, path):
    status, headers, data = request(dashboard, path)
    assert status == 200 and data
    if path in ("/", "/index.html"):
        assert b"__SENTINEL_TOKEN__" not in data
        assert dashboard.token.encode() in data
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    "path", ["/../pyproject.toml", "/sentinel.db", "/api/alerts/no/evidence", "/missing"]
)
def test_dashboard_has_no_file_browser(dashboard, path):
    assert request(dashboard, path)[0] == 404


def test_dashboard_rejects_foreign_host_origin_and_missing_token(dashboard):
    assert request(dashboard, headers={"Host": "evil.example"})[0] == 403
    assert request(dashboard, headers={"Origin": "https://evil.example"})[0] == 403
    assert request(dashboard, "/api/scan", method="POST")[0] == 403
    headers = {"X-Sentinel-Token": dashboard.token, "Origin": dashboard.url}
    assert request(dashboard, "/api/scan", method="POST", headers=headers)[0] == 202
    assert request(dashboard, "/missing", method="POST")[0] == 404


@pytest.mark.parametrize("length", ["bad", "-1", "2048"])
def test_dashboard_rejects_unbounded_post_body(dashboard, length):
    headers = {"X-Sentinel-Token": dashboard.token, "Content-Length": length}
    assert request(dashboard, "/api/scan", method="POST", headers=headers)[0] == 400


def test_dashboard_accepts_small_post_body(dashboard):
    status, _, _ = request(
        dashboard,
        "/api/scan",
        method="POST",
        headers={"X-Sentinel-Token": dashboard.token},
        body=b"{}",
    )
    assert status == 202


def test_dashboard_port_rejected(tmp_path):
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *_a, **_k: batch([]))
    with pytest.raises(ValidationError):
        DashboardServer(monitor, 65536)
    store.close()


def test_serve_cleanup_and_browser_open(tmp_path, monkeypatch):
    lifecycle = []

    class FakeServer:
        url = "http://127.0.0.1:1234"

        def __init__(self, *_a):
            pass

        def serve_forever(self, **_k):
            raise KeyboardInterrupt

        def server_close(self):
            lifecycle.append("closed")

    monkeypatch.setattr(live, "DashboardServer", FakeServer)
    monkeypatch.setattr(live.LiveMonitor, "start", lambda _: None)
    monkeypatch.setattr(live.webbrowser, "open", lambda url: lifecycle.append(url))
    with pytest.raises(KeyboardInterrupt):
        live.serve(tmp_path, open_browser=True)
    assert lifecycle == ["http://127.0.0.1:1234", "closed"]
