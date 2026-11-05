"""Durable unread and native-attempt metadata without replay or startup storms."""

import json
import sqlite3
import threading
from contextlib import closing
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection

import pytest

from sauron_sentinel import live
from sauron_sentinel.engine import RuleEngine
from sauron_sentinel.live import DashboardServer, EventStore, LiveMonitor
from sauron_sentinel.models import normalize
from sauron_sentinel.preferences import default_preferences
from sauron_sentinel.rules import load_rules
from sauron_sentinel.windows import CollectionBatch

START = datetime(2026, 1, 2, tzinfo=UTC)


def event(number=0, *, seconds=0, kind="service.installed"):
    return normalize(
        {
            "schema_version": 1,
            "timestamp": (START + timedelta(seconds=seconds)).isoformat(),
            "source": "windows-eventlog",
            "kind": kind,
            "device_id": "windows-notification-test",
            "synthetic": False,
            "attributes": {"record_id": number, "service_name": "Private service detail"},
        }
    )


def batch(events, *, partial=False):
    sources = [{"channel": "System", "status": "ok", "event_count": len(events)}]
    if partial:
        sources.append(
            {"channel": "Security", "status": "unavailable", "error": "permission_denied"}
        )
    return CollectionBatch(events, sources)


class Notifier:
    def __init__(self, *, available=True, error=None, result=True):
        self.available, self.error, self.result = available, error, result
        self.calls = []
        self.on_notify = None

    def snapshot(self):
        return {"available": self.available, "last_error": self.error}

    def notify(self, *, test=False):
        self.calls.append(test)
        if self.on_notify:
            self.on_notify()
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(live, "_now", lambda: START)


def make_monitor(tmp_path, batches, *, enabled=True, notifier=None, **kwargs):
    store = EventStore(tmp_path, **kwargs)
    store.set_preferences(default_preferences() | {"notifications_enabled": enabled})
    responses = iter(batches)
    notifier = notifier if notifier is not None else Notifier()
    monitor = LiveMonitor(store, collector=lambda *a, **k: next(responses), notifier=notifier)
    return store, monitor, notifier


def test_first_partial_batch_is_read_then_new_alert_is_unread_and_attempted_once(tmp_path):
    first, second = event(0, seconds=-1), event(1, seconds=0)
    store, monitor, notifier = make_monitor(
        tmp_path, [batch([first], partial=True), batch([second]), batch([second])]
    )
    try:
        assert monitor.scan()
        state = monitor.state()
        assert state["alerts"][0]["unread"] is False
        assert state["notifications"]["unread_count"] == 0
        assert state["notifications"]["last_attempt_at"] is None
        assert notifier.calls == []
        assert state["health"]["status"] == "partial"
        assert monitor.scan() and monitor.scan()
        state = monitor.state()
        assert state["notifications"] == {
            "available": True,
            "unread_count": 1,
            "last_attempt_at": "2026-01-02T00:00:00.000000Z",
            "last_attempt_status": "queued",
            "last_error": None,
            "delivery_guaranteed": False,
        }
        assert notifier.calls == [False]
        newest = state["alerts"][0]
        evidence = store.evidence(newest["alert_id"])
        assert evidence["unread"] is True
        assert "unread" not in evidence["alert"]
        assert evidence["review"]["status"] == "new"
        assert store.notifications()["unread_count"] == 1  # Evidence GET semantics are read-only.
    finally:
        monitor.stop()
        store.close()


def test_startup_even_current_timestamp_alerts_are_baseline(tmp_path):
    store, monitor, notifier = make_monitor(tmp_path, [batch([event()])])
    try:
        assert monitor.scan()
        assert notifier.calls == []
        assert monitor.state()["notifications"]["unread_count"] == 0
    finally:
        monitor.stop()
        store.close()


def test_backfill_and_late_replay_never_create_unread_or_attempts(tmp_path):
    store, monitor, notifier = make_monitor(
        tmp_path,
        [batch([]), batch([event(1, seconds=-2)]), batch([event(2, seconds=-3)])],
    )
    try:
        assert monitor.scan() and monitor.scan() and monitor.scan()
        assert monitor.state()["notifications"]["unread_count"] == 0
        assert monitor.state()["monitor"]["late_events"] == 1
        assert notifier.calls == []
        # Recovery rebuild creates the late alert as read without scheduling delivery.
        monitor._needs_rebuild = True
        monitor.collector = lambda *a, **k: batch([])
        assert monitor.scan()
        assert monitor.state()["summary"]["alerts_total"] == 2
        assert monitor.state()["notifications"]["unread_count"] == 0
        assert notifier.calls == []
    finally:
        monitor.stop()
        store.close()


def test_restart_preserves_unread_claim_and_review_without_repeating(tmp_path):
    observation = event()
    store, monitor, notifier = make_monitor(tmp_path, [batch([]), batch([observation])])
    assert monitor.scan() and monitor.scan()
    alert_id = monitor.state()["alerts"][0]["alert_id"]
    store.set_review(alert_id, "expected", "One reviewed occurrence")
    monitor.stop()
    store.close()
    store = EventStore(tmp_path)
    reopened = LiveMonitor(store, collector=lambda *a, **k: batch([observation]), notifier=notifier)
    try:
        assert reopened.scan()
        state = reopened.state()
        assert state["notifications"]["unread_count"] == 1
        assert state["notifications"]["last_attempt_status"] == "queued"
        assert state["alerts"][0]["review"]["status"] == "expected"
        assert notifier.calls == [False]
        before = store._db.execute("SELECT payload,evidence FROM alerts").fetchall()
        assert store.mark_read(alert_id) == {"unread": False, "unread_count": 0}
        assert store.mark_read(alert_id) == {"unread": False, "unread_count": 0}
        assert store.evidence(alert_id)["review"]["status"] == "expected"
        assert store._db.execute("SELECT payload,evidence FROM alerts").fetchall() == before
    finally:
        reopened.stop()
        store.close()
    store = EventStore(tmp_path)
    try:
        assert store.evidence(alert_id)["unread"] is False
    finally:
        store.close()


def test_enabling_later_never_notifies_older_alerts(tmp_path):
    first, second = event(0), event(1, seconds=1)
    store, monitor, notifier = make_monitor(
        tmp_path, [batch([]), batch([first]), batch([first]), batch([second])], enabled=False
    )
    try:
        assert monitor.scan() and monitor.scan()
        assert monitor.state()["notifications"]["unread_count"] == 1
        assert notifier.calls == []
        monitor.set_preferences(default_preferences() | {"notifications_enabled": True})
        assert monitor.scan()
        assert notifier.calls == []
        assert monitor.scan()
        assert notifier.calls == [False]
        assert monitor.state()["notifications"]["unread_count"] == 2
    finally:
        monitor.stop()
        store.close()


@pytest.mark.parametrize(
    "severity,kind,expected",
    [
        ("low", "service.installed", 1),
        ("medium", "service.installed", 1),
        ("high", "service.installed", 0),
        ("high", "log.cleared", 1),
    ],
)
def test_severity_only_filters_native_attempts(tmp_path, severity, kind, expected):
    store, monitor, notifier = make_monitor(tmp_path, [batch([]), batch([event(kind=kind)])])
    try:
        monitor.set_preferences(
            default_preferences()
            | {
                "notifications_enabled": True,
                "minimum_severity": severity,
            }
        )
        assert monitor.scan() and monitor.scan()
        assert len(notifier.calls) == expected
        assert monitor.state()["notifications"]["unread_count"] == 1
    finally:
        monitor.stop()
        store.close()


@pytest.mark.parametrize("result", [False, OSError("private machine and service path")])
def test_failed_native_attempt_is_claimed_before_callback_and_not_retried(tmp_path, result):
    notifier = Notifier(result=result)
    store, monitor, _ = make_monitor(tmp_path, [batch([]), batch([event()])], notifier=notifier)
    seen = []

    def observe_claim():
        with sqlite_connection(tmp_path) as connection:
            seen.append(
                connection.execute("SELECT attempt_status FROM alert_notifications").fetchone()[0]
            )

    notifier.on_notify = observe_claim
    try:
        assert monitor.scan() and monitor.scan()
        assert seen == ["attempting"]
        state = monitor.state()
        assert state["monitor"]["last_error"] is None
        assert state["notifications"]["last_attempt_status"] == "failed"
        assert state["notifications"]["last_error"] == "notification_failed"
        assert "private" not in json.dumps(state).lower().replace("private service detail", "")
        alert_id = state["alerts"][0]["alert_id"]
        assert not monitor._notify(alert_id=alert_id)
        assert notifier.calls == [False]
    finally:
        monitor.stop()
        store.close()


def sqlite_connection(tmp_path):
    return closing(sqlite3.connect(tmp_path / "sentinel.db"))


def test_unavailable_native_still_marks_new_alert_unread(tmp_path):
    notifier = Notifier(available=False, error="native_unavailable")
    store, monitor, _ = make_monitor(tmp_path, [batch([]), batch([event()])], notifier=notifier)
    try:
        assert monitor.scan() and monitor.scan()
        state = monitor.state()
        assert state["notifications"]["available"] is False
        assert state["notifications"]["unread_count"] == 1
        assert state["notifications"]["last_attempt_at"] is None
        assert notifier.calls == []
    finally:
        monitor.stop()
        store.close()


@pytest.mark.parametrize("failure_point", ["claim_notification", "record_notification"])
def test_notification_metadata_failure_does_not_abort_live_batch(
    tmp_path, monkeypatch, failure_point
):
    store, monitor, notifier = make_monitor(
        tmp_path, [batch([]), batch([event(0), event(1, seconds=1)])]
    )

    def fail_metadata(*args, **kwargs):
        raise sqlite3.OperationalError("private notification database detail")

    try:
        assert monitor.scan()
        with monkeypatch.context() as patch:
            patch.setattr(store, failure_point, fail_metadata)
            assert monitor.scan()
        state = monitor.state()
        assert state["summary"]["alerts_total"] == 2
        assert state["notifications"]["unread_count"] == 2
        assert state["monitor"]["last_error"] is None
        assert state["notifications"]["last_error"] == "notification_failed"
        assert "private notification database detail" not in json.dumps(state)
        expected_calls = 0 if failure_point == "claim_notification" else 2
        assert len(notifier.calls) == expected_calls
        monitor._needs_rebuild = True
        monitor.collector = lambda *a, **k: batch([])
        assert monitor.scan()
        assert len(notifier.calls) == expected_calls
    finally:
        monitor.stop()
        store.close()


@pytest.mark.parametrize("error", ["private machine path", {}, ["private detail"]])
def test_native_snapshot_errors_are_sanitized(tmp_path, error):
    store, monitor, _ = make_monitor(tmp_path, [], notifier=Notifier(error=error))
    try:
        assert monitor.state()["notifications"]["last_error"] in {
            "native_unavailable",
            "notification_failed",
        }
        assert "private" not in json.dumps(monitor.state())
    finally:
        monitor.stop()
        store.close()


def test_whole_collection_failure_does_not_finish_baseline(tmp_path):
    store, monitor, notifier = make_monitor(tmp_path, [])

    def fail(*a, **k):
        raise OSError("private collector detail")

    try:
        monitor.collector = fail
        assert not monitor.scan()
        monitor.collector = lambda *a, **k: batch([event()])
        assert monitor.scan()
        assert notifier.calls == []
        assert monitor.state()["notifications"]["unread_count"] == 0
    finally:
        monitor.stop()
        store.close()


def test_metadata_pruned_on_retention_and_open(tmp_path):
    store, monitor, _ = make_monitor(
        tmp_path, [batch([]), batch([event(0)]), batch([event(1, seconds=1)])], max_alerts=1
    )
    assert monitor.scan() and monitor.scan()
    old_id = monitor.state()["alerts"][0]["alert_id"]
    assert monitor.scan()
    assert store.mark_read(old_id) is None
    assert store._db.execute("SELECT count(*) FROM alert_notifications").fetchone()[0] == 1
    assert store.notifications()["unread_count"] == 1
    with store._db:
        store._db.execute("DELETE FROM alerts")
    monitor.stop()
    store.close()
    store = EventStore(tmp_path)
    try:
        assert store.notifications()["unread_count"] == 0
        assert store._db.execute("SELECT count(*) FROM alert_notifications").fetchone()[0] == 0
    finally:
        store.close()


@pytest.fixture
def dashboard(tmp_path):
    store, monitor, notifier = make_monitor(tmp_path, [batch([]), batch([event()])], enabled=False)
    assert monitor.scan() and monitor.scan()
    server = DashboardServer(monitor, 0)
    server.read_path = f"/api/alerts/{monitor.state()['alerts'][0]['alert_id']}/read"
    server.notifier = notifier
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        monitor.stop()
        store.close()


def request(server, path, *, body=b"{}", headers=None, method="POST"):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.request(method, path, body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def test_http_read_is_explicit_idempotent_and_separate_from_review(dashboard):
    headers = {"X-Sentinel-Token": dashboard.token, "Origin": dashboard.url}
    evidence_path = dashboard.read_path.replace("/read", "/evidence")
    assert request(dashboard, evidence_path, method="GET")[1]["unread"] is True
    assert request(dashboard, "/api/state", method="GET")[1]["notifications"]["unread_count"] == 1
    for _ in range(2):
        assert request(dashboard, dashboard.read_path, headers=headers) == (
            200,
            {"unread": False, "unread_count": 0},
        )
    evidence = request(dashboard, evidence_path, method="GET")[1]
    assert evidence["unread"] is False and evidence["review"]["status"] == "new"
    export = request(dashboard, "/api/export", method="GET")[1]
    assert export["alerts"][0]["unread"] is False
    assert export["preferences"]["notifications_enabled"] is False


def test_http_notification_test_requires_opt_in_and_availability_without_fake_alert(dashboard):
    path = "/api/notifications/test"
    headers = {"X-Sentinel-Token": dashboard.token}
    before = dashboard.monitor.state()["summary"]
    assert request(dashboard, path, headers=headers) == (409, {"error": "notifications_disabled"})
    dashboard.monitor.set_preferences(default_preferences() | {"notifications_enabled": True})
    dashboard.notifier.available = False
    assert request(dashboard, path, headers=headers) == (
        503,
        {"error": "notifications_unavailable"},
    )
    dashboard.notifier.available = True
    assert request(dashboard, path, headers=headers) == (202, {"status": "queued"})
    assert dashboard.notifier.calls == [True]
    assert dashboard.monitor.state()["notifications"]["last_attempt_status"] == "queued"
    assert dashboard.monitor.state()["summary"] == before
    dashboard.notifier.result = OSError("private native diagnostic")
    assert request(dashboard, path, headers=headers) == (503, {"error": "notification_failed"})
    assert dashboard.monitor.state()["notifications"]["last_error"] == "notification_failed"


@pytest.mark.parametrize("endpoint", ["read", "test"])
def test_http_new_mutations_keep_auth_origin_host_and_body_guards(dashboard, endpoint):
    path = dashboard.read_path if endpoint == "read" else "/api/notifications/test"
    headers = {"X-Sentinel-Token": dashboard.token}
    for guarded in (
        {},
        {"X-Sentinel-Token": "wrong"},
        {"X-Sentinel-Token": "é"},
        headers | {"Origin": "https://evil.example"},
        headers | {"Host": "evil.example"},
    ):
        assert request(dashboard, path, body=None, headers=guarded)[0] == 403
    for invalid_body in (b"", b"null", b"[]", b'{"unread":false}', b'{"x":1,"x":2}', b"\xff"):
        assert request(dashboard, path, body=invalid_body, headers=headers) == (
            400,
            {"error": "invalid_body"},
        )
    for bound in (
        {"Content-Length": "bad"},
        {"Content-Length": "-1"},
        {"Content-Length": "1025"},
        {"Transfer-Encoding": "chunked"},
    ):
        assert request(dashboard, path, body=None, headers=headers | bound) == (
            400,
            {"error": "invalid_body"},
        )
    assert dashboard.monitor.state()["notifications"]["unread_count"] == 1


def test_http_unknown_or_invalid_read_ids_do_not_mutate(dashboard):
    headers = {"X-Sentinel-Token": dashboard.token}
    for invalid in ("f" * 64, "F" * 64, "f" * 63, "f" * 65, "x'OR'1'='1"):
        assert request(dashboard, f"/api/alerts/{invalid}/read", headers=headers)[0] == 404
    assert dashboard.monitor.state()["notifications"]["unread_count"] == 1


def test_concurrent_claims_are_at_most_once(tmp_path):
    store = EventStore(tmp_path)
    observation = event()
    store.add_events([observation])
    alert = RuleEngine(load_rules()).process(observation)[0]
    store.add_alert(alert, unread=True)
    results = []
    workers = [
        threading.Thread(
            target=lambda: results.append(
                store.claim_notification(alert.alert_id, "2026-01-02T00:00:00Z")
            )
        )
        for _ in range(8)
    ]
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(3)
        assert results.count(True) == 1 and results.count(False) == 7
    finally:
        store.close()
