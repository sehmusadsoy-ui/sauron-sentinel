"""Per-alert human review is durable metadata, never a change to detection evidence."""

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
from sauron_sentinel.models import ValidationError, normalize
from sauron_sentinel.rules import load_rules
from sauron_sentinel.windows import CollectionBatch


def observation(number=0):
    return normalize(
        {
            "schema_version": 1,
            "timestamp": (datetime(2026, 1, 2, tzinfo=UTC) + timedelta(seconds=number)).isoformat(),
            "source": "windows-eventlog",
            "kind": "service.installed",
            "device_id": "windows-review-test",
            "synthetic": False,
            "attributes": {"record_id": number, "service_name": "Same normal service"},
        }
    )


def add_alert(store, number=0):
    event = observation(number)
    store.add_events([event])
    alert = RuleEngine(load_rules()).process(event)[0]
    store.add_alert(alert)
    return alert


def raw_evidence(store):
    return store._db.execute(
        "SELECT alert_id,payload,evidence FROM alerts ORDER BY alert_id"
    ).fetchall()


def test_legacy_migration_preserves_exact_payloads_and_survives_restart(tmp_path):
    event = observation()
    alert = RuleEngine(load_rules()).process(event)[0]
    # v0.3 did not set user_version. Preserve even its original JSON formatting.
    alert_text = json.dumps(alert.to_dict(), indent=2)
    event_text = json.dumps(event.to_dict(), indent=1)
    evidence_text = json.dumps([event.to_dict()], indent=3)
    database = tmp_path / "sentinel.db"
    with closing(sqlite3.connect(database)) as old, old:
        old.executescript(
            "CREATE TABLE events(event_id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,"
            "payload TEXT NOT NULL);"
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,"
            "payload TEXT NOT NULL,evidence TEXT NOT NULL);"
        )
        old.execute("INSERT INTO events VALUES(?,?,?)", (event.event_id, "2026", event_text))
        old.execute(
            "INSERT INTO alerts VALUES(?,?,?,?)",
            (alert.alert_id, "2026", alert_text, evidence_text),
        )
    store = EventStore(tmp_path)
    try:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == 2
        initial = store.evidence(alert.alert_id)
        assert initial["review"] == {"status": "new", "note": "", "updated_at": None}
        assert initial["alert"] == alert.to_dict()
        assert initial["events"] == [event.to_dict()]
        before = raw_evidence(store)
        result = store.set_review(alert.alert_id, "expected", "Kurulumla eşleşti.\nYerel not\t✓")
        assert result["status"] == "expected" and result["updated_at"].endswith("Z")
        assert raw_evidence(store) == before == [(alert.alert_id, alert_text, evidence_text)]
        assert store._db.execute("SELECT payload FROM events").fetchone()[0] == event_text
        assert store.snapshot()["alerts"][0]["review"] == result
        assert "review" not in store.evidence(alert.alert_id)["alert"]
    finally:
        store.close()
    store = EventStore(tmp_path)
    try:
        assert store.evidence(alert.alert_id)["review"] == result
        assert raw_evidence(store) == before
        # Engine replay must not overwrite a human review or mutate stored evidence.
        monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([], []))
        assert monitor.state()["alerts"][0]["review"] == result
        assert raw_evidence(store) == before
        monitor.stop()
    finally:
        store.close()


def test_review_updates_and_reset_apply_only_to_one_alert(tmp_path, monkeypatch):
    store = EventStore(tmp_path)
    try:
        first, second = add_alert(store), add_alert(store, 1)
        before = raw_evidence(store)
        clock = datetime(2026, 1, 3, tzinfo=UTC)
        monkeypatch.setattr(live, "_now", lambda: clock)
        initial = store.set_review(first.alert_id, "expected", "Known service")
        assert store.evidence(second.alert_id)["review"]["status"] == "new"
        clock += timedelta(seconds=1)
        updated = store.set_review(first.alert_id, "reviewed", "Rechecked")
        assert updated["updated_at"] > initial["updated_at"]
        assert store.evidence(first.alert_id)["review"] == updated
        reset = store.set_review(first.alert_id, "new", "")
        assert reset == {"status": "new", "note": "", "updated_at": updated["updated_at"]}
        assert raw_evidence(store) == before
        assert store.set_review("f" * 64, "reviewed", "") is None
        assert store._db.execute("SELECT count(*) FROM alert_reviews").fetchone()[0] == 1
        # API snapshots are detached values; callers cannot modify persisted notes.
        snapshot = store.snapshot()
        snapshot["alerts"][0]["review"]["note"] = "changed outside storage"
        assert store.evidence(second.alert_id)["review"]["note"] == ""
    finally:
        store.close()


def test_pruning_removes_review_without_trusting_same_future_service(tmp_path):
    store = EventStore(tmp_path, max_events=1, max_alerts=1)
    try:
        first = add_alert(store)
        store.set_review(first.alert_id, "expected", "Installer")
        second = add_alert(store, 1)
        assert store.evidence(first.alert_id) is None
        assert store.evidence(second.alert_id)["review"] == {
            "status": "new",
            "note": "",
            "updated_at": None,
        }
        assert store._db.execute("SELECT count(*) FROM alert_reviews").fetchone()[0] == 0
        assert store.evidence(second.alert_id)["events"][0]["event_id"] == observation(1).event_id
    finally:
        store.close()


def test_reopen_cleans_orphan_review_metadata(tmp_path):
    store = EventStore(tmp_path)
    first = add_alert(store)
    store.set_review(first.alert_id, "reviewed", "Orphan fixture")
    with store._db:
        store._db.execute("DELETE FROM alerts")
    store.close()
    reopened = EventStore(tmp_path)
    try:
        assert reopened._db.execute("SELECT count(*) FROM alert_reviews").fetchone()[0] == 0
    finally:
        reopened.close()


def test_future_schema_rejected_without_mutation_and_connection_closed(tmp_path, monkeypatch):
    database = tmp_path / "sentinel.db"
    with closing(sqlite3.connect(database)) as future, future:
        future.execute("CREATE TABLE future_records(value TEXT)")
        future.execute("INSERT INTO future_records VALUES('preserve me')")
        future.execute("PRAGMA user_version=99")
    before = database.read_bytes()
    connections = []
    connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(live.sqlite3, "connect", recording_connect)
    with pytest.raises(sqlite3.DatabaseError, match="Unsupported local storage schema"):
        EventStore(tmp_path)
    assert database.read_bytes() == before
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_failed_migration_rolls_back_schema_and_version(tmp_path, monkeypatch):
    database = tmp_path / "sentinel.db"
    with closing(sqlite3.connect(database)) as old, old:
        old.execute("CREATE TABLE preserved(value TEXT)")
        old.execute("INSERT INTO preserved VALUES('keep')")
    connect = sqlite3.connect
    connections = []

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("CREATE TABLE alert_reviews"):
                raise sqlite3.OperationalError("Controlled migration failure")
            return super().execute(sql, *args)

    def failing_connect(*args, **kwargs):
        connection = connect(*args, **kwargs, factory=FailingConnection)
        connections.append(connection)
        return connection

    monkeypatch.setattr(live.sqlite3, "connect", failing_connect)
    with pytest.raises(sqlite3.OperationalError, match="Controlled"):
        EventStore(tmp_path)
    with closing(connect(database)) as database, database:
        assert database.execute("PRAGMA user_version").fetchone()[0] == 0
        assert database.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
            ("preserved",)
        ]
        assert database.execute("SELECT value FROM preserved").fetchone()[0] == "keep"
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


@pytest.mark.parametrize(
    "status,note",
    [
        (None, ""),
        (True, ""),
        ([], ""),
        ("trusted", ""),
        ("new", None),
        ("new", 5),
        ("new", "x" * 501),
        ("new", "\x00"),
        ("new", "\r"),
        ("new", "\x7f"),
        ("new", "\x85"),
        ("new", "\u202e"),
        ("new", "\ud800"),
    ],
)
def test_store_rejects_invalid_review_without_mutation(tmp_path, status, note):
    store = EventStore(tmp_path)
    try:
        alert = add_alert(store)
        before = raw_evidence(store)
        with pytest.raises(ValidationError):
            store.set_review(alert.alert_id, status, note)
        assert store.evidence(alert.alert_id)["review"]["updated_at"] is None
        assert raw_evidence(store) == before
    finally:
        store.close()


@pytest.fixture
def dashboard(tmp_path):
    store = EventStore(tmp_path)
    alert = add_alert(store)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([], []))
    server = DashboardServer(monitor, 0)
    server.review_path = f"/api/alerts/{alert.alert_id}/review"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        monitor.stop()
        store.close()


def request(server, *, body=None, headers=None, path=None, method="POST"):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.request(method, path or server.review_path, body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def post_review(server, payload, *, headers=None, path=None):
    request_headers = {"X-Sentinel-Token": server.token, "Origin": server.url}
    request_headers.update(headers or {})
    return request(
        server,
        body=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
        headers=request_headers,
        path=path,
    )


def test_http_review_unicode_limits_and_evidence_contract(dashboard):
    store = dashboard.monitor.store
    before = raw_evidence(store)
    note = "ş" * 500
    status, result = post_review(dashboard, {"status": "expected", "note": note})
    assert status == 200
    assert result["review"]["status"] == "expected" and result["review"]["note"] == note
    status, evidence = request(
        dashboard, path=dashboard.review_path.replace("/review", "/evidence"), method="GET"
    )
    assert status == 200 and evidence["review"] == result["review"]
    assert evidence["explanation"]["rule_id"] == "windows-service-installed"
    assert "review" not in evidence["alert"]
    status, state = request(dashboard, path="/api/state", method="GET")
    assert status == 200 and state["alerts"][0]["review"] == result["review"]
    assert post_review(dashboard, {"status": "new", "note": "ş" * 501})[0] == 400
    # Astral Unicode is one codepoint, while JSON transport may use surrogate pairs.
    status, result = post_review(dashboard, {"status": "reviewed", "note": "😀" * 500})
    assert status == 200 and result["review"]["note"] == "😀" * 500
    assert post_review(dashboard, {"status": "reviewed", "note": "😀" * 501}) == (
        400,
        {"error": "invalid_review"},
    )
    status, result = request(
        dashboard,
        body=json.dumps({"status": "reviewed", "note": "😀" * 500}, ensure_ascii=False).encode(),
        headers={"X-Sentinel-Token": dashboard.token},
    )
    assert status == 200 and result["review"]["note"] == "😀" * 500
    assert post_review(dashboard, {"status": "reviewed", "note": "line\nwith\ttab"})[0] == 200
    plain_text = "<script>text only</script> '; DROP TABLE alerts; --"
    status, result = post_review(dashboard, {"status": "reviewed", "note": plain_text})
    assert status == 200 and result["review"]["note"] == plain_text
    assert raw_evidence(store) == before


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{",
        b"[]",
        b"null",
        b'{"status":"new"}',
        b'{"note":""}',
        b'{"status":"new","note":"","trust_service":true}',
        b'{"status":"new","status":"expected","note":""}',
        b'{"status":"new","note":"","note":"override"}',
        b'{"status":false,"note":""}',
        b'{"status":{},"note":""}',
        b'{"status":"new","note":null}',
        b'{"status":"new","note":"\\u0000"}',
        b'{"status":"new","note":"\\ud800"}',
        b'{"status":"new","note":"\xff"}',
        b"[" * 1500,
    ],
)
def test_http_rejects_invalid_review_without_mutating_metadata(dashboard, body):
    before = raw_evidence(dashboard.monitor.store)
    status, data = request(dashboard, body=body, headers={"X-Sentinel-Token": dashboard.token})
    assert (status, data) == (400, {"error": "invalid_review"})
    assert dashboard.monitor.state()["alerts"][0]["review"]["updated_at"] is None
    assert raw_evidence(dashboard.monitor.store) == before


def test_http_guards_and_unknown_ids(dashboard):
    for headers in (
        {},
        {"X-Sentinel-Token": "incorrect"},
        {"X-Sentinel-Token": "é"},
        {"X-Sentinel-Token": dashboard.token, "Origin": "https://evil.example"},
        {"X-Sentinel-Token": dashboard.token, "Host": "evil.example"},
    ):
        # Guards reject before reading a body; avoid an unread-body TCP reset on Windows.
        assert request(dashboard, headers=headers)[0] == 403
    assert post_review(
        dashboard, {"status": "reviewed", "note": ""}, path="/api/alerts/" + "f" * 64 + "/review"
    ) == (404, {"error": "not_found"})
    for invalid in ("not-an-id", "A" * 64, "f" * 63, "f" * 65, "x'OR'1'='1"):
        assert (
            request(
                dashboard,
                headers={"X-Sentinel-Token": dashboard.token},
                path=f"/api/alerts/{invalid}/review",
            )[0]
            == 404
        )
    assert (
        dashboard.monitor.store._db.execute("SELECT count(*) FROM alert_reviews").fetchone()[0] == 0
    )


def test_http_review_body_bound_keeps_scan_limit(dashboard):
    for headers in (
        {"Content-Length": "bad"},
        {"Content-Length": "-1"},
        {"Content-Length": "8193"},
        {"Transfer-Encoding": "chunked"},
    ):
        status, data = request(dashboard, headers={"X-Sentinel-Token": dashboard.token, **headers})
        assert (status, data) == (400, {"error": "invalid_body"})
    payload = b'{"status":"reviewed","note":"ok"}'
    status, _ = request(
        dashboard,
        body=payload + b" " * (8192 - len(payload)),
        headers={"X-Sentinel-Token": dashboard.token},
    )
    assert status == 200
    status, data = request(
        dashboard,
        path="/api/scan",
        body=b" " * 1025,
        headers={"X-Sentinel-Token": dashboard.token},
    )
    assert (status, data) == (400, {"error": "invalid_body"})


def test_review_and_retention_are_serialized(tmp_path):
    store = EventStore(tmp_path, max_alerts=1)
    first = add_alert(store)
    failures = []
    barrier = threading.Barrier(2)

    def review():
        try:
            barrier.wait(timeout=3)
            for _ in range(30):
                store.set_review(first.alert_id, "expected", "Known one alert")
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=review)
    try:
        worker.start()
        barrier.wait(timeout=3)
        second = add_alert(store, 1)
        worker.join(timeout=3)
        assert not worker.is_alive() and not failures
        assert store._db.execute("SELECT count(*) FROM alert_reviews").fetchone()[0] == 0
        assert store.evidence(second.alert_id)["review"]["status"] == "new"
    finally:
        worker.join(timeout=3)
        store.close()
