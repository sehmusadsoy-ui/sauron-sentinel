"""Preference migrations, exact validation, persistence, and polling updates."""

import json
import sqlite3
import threading
from contextlib import closing
from http.client import HTTPConnection

import pytest

from sauron_sentinel import cli, live
from sauron_sentinel.live import DashboardServer, EventStore, LiveMonitor
from sauron_sentinel.models import ValidationError
from sauron_sentinel.preferences import default_preferences, validate_preferences
from sauron_sentinel.windows import CollectionBatch


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("schema_version", "1"),
        ("notifications_enabled", 1),
        ("notifications_enabled", "false"),
        ("notifications_enabled", None),
        ("minimum_severity", "critical"),
        ("minimum_severity", []),
        ("minimum_severity", None),
        ("scan_interval_seconds", True),
        ("scan_interval_seconds", 15.0),
        ("scan_interval_seconds", "15"),
        ("scan_interval_seconds", 4),
        ("scan_interval_seconds", 3601),
        ("scan_interval_seconds", None),
    ],
)
def test_preferences_reject_invalid_types_without_mutation(tmp_path, key, value):
    store = EventStore(tmp_path)
    try:
        preferences = default_preferences()
        preferences[key] = value
        with pytest.raises(ValidationError):
            store.set_preferences(preferences)
        assert store.preferences() == {
            "preferences": default_preferences(),
            "preferences_status": "ok",
        }
    finally:
        store.close()


@pytest.mark.parametrize("value", [None, [], {}, {"notifications_enabled": False}])
def test_preferences_require_complete_shape(value):
    with pytest.raises(ValidationError):
        validate_preferences(value)
    extra = default_preferences() | {"unexpected": True}
    with pytest.raises(ValidationError):
        validate_preferences(extra)


@pytest.mark.parametrize("interval", [5, 15, 30, 60, 300, 47, 3600])
def test_preferences_survive_restart_and_custom_interval(tmp_path, interval):
    store = EventStore(tmp_path)
    value = default_preferences() | {
        "notifications_enabled": True,
        "minimum_severity": "high",
        "scan_interval_seconds": interval,
    }
    store.set_preferences(value)
    value["minimum_severity"] = "low"
    store.close()
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([], []))
    try:
        assert monitor.interval == interval
        assert monitor.state()["monitor"]["interval_seconds"] == interval
        preferences = store.preferences()["preferences"]
        assert preferences["notifications_enabled"] is True
        assert preferences["minimum_severity"] == "high"
        preferences["notifications_enabled"] = False
        assert store.preferences()["preferences"]["notifications_enabled"] is True
    finally:
        monitor.stop()
        store.close()


def test_explicit_constructor_interval_is_persisted(tmp_path):
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, interval=47, collector=lambda *a, **k: CollectionBatch([], []))
    try:
        assert store.preferences()["preferences"]["scan_interval_seconds"] == 47
    finally:
        monitor.stop()
        store.close()


@pytest.mark.parametrize("interval", [True, False, 15.0, "15"])
def test_constructor_interval_requires_integer(tmp_path, interval):
    store = EventStore(tmp_path)
    try:
        with pytest.raises(ValidationError):
            LiveMonitor(store, interval=interval)
    finally:
        store.close()


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "{broken private user detail",
        "[]",
        '{"schema_version":1,"schema_version":1}',
        json.dumps(default_preferences() | {"notifications_enabled": "yes"}),
        json.dumps(default_preferences() | {"scan_interval_seconds": 0}),
        json.dumps(default_preferences() | {"extra": "private detail"}),
    ],
)
def test_corrupt_stored_preferences_reset_safely_and_visibly(tmp_path, payload):
    store = EventStore(tmp_path)
    with store._db:
        if payload is None:
            store._db.execute("DELETE FROM app_preferences")
        else:
            store._db.execute("UPDATE app_preferences SET payload=?", (payload,))
    store.close()
    store = EventStore(tmp_path)
    try:
        assert store.preferences() == {
            "preferences": default_preferences(),
            "preferences_status": "reset_invalid",
        }
        assert json.loads(
            store._db.execute("SELECT payload FROM app_preferences").fetchone()[0]
        ) == (default_preferences())
        store.set_preferences(default_preferences())
        assert store.preferences()["preferences_status"] == "ok"
    finally:
        store.close()


def make_v1(database):
    with closing(sqlite3.connect(database)) as old, old:
        old.executescript(
            "CREATE TABLE events(event_id TEXT PRIMARY KEY,timestamp TEXT,payload TEXT);"
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY,timestamp TEXT,payload TEXT,evidence TEXT);"
            "CREATE TABLE alert_reviews(alert_id TEXT PRIMARY KEY,status TEXT,note TEXT,updated_at TEXT);"
            "INSERT INTO alerts VALUES('original','2026','{  \"original\": true }','[ ]');"
            "INSERT INTO alert_reviews VALUES('original','expected','preserve ✓','2026');"
            "PRAGMA user_version=1;"
        )


def test_v1_migration_is_additive_and_existing_alerts_are_read(tmp_path):
    make_v1(tmp_path / "sentinel.db")
    store = EventStore(tmp_path)
    try:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert store._db.execute("SELECT * FROM alerts").fetchone() == (
            "original",
            "2026",
            '{  "original": true }',
            "[ ]",
        )
        assert store._db.execute("SELECT * FROM alert_reviews").fetchone() == (
            "original",
            "expected",
            "preserve ✓",
            "2026",
        )
        assert store.notifications()["unread_count"] == 0
        assert store._db.execute("SELECT * FROM alert_notifications").fetchone() == (
            "original",
            0,
            None,
            None,
        )
    finally:
        store.close()


def test_failed_v1_to_v2_migration_rolls_back_and_closes_connection(tmp_path, monkeypatch):
    database = tmp_path / "sentinel.db"
    make_v1(database)
    connect = sqlite3.connect
    connections = []

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("CREATE TABLE notification_state"):
                raise sqlite3.OperationalError("Controlled migration failure")
            return super().execute(sql, *args)

    def failing_connect(*args, **kwargs):
        connection = connect(*args, **kwargs, factory=FailingConnection)
        connections.append(connection)
        return connection

    monkeypatch.setattr(live.sqlite3, "connect", failing_connect)
    with pytest.raises(sqlite3.OperationalError, match="Controlled"):
        EventStore(tmp_path)
    with closing(connect(database)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        assert "app_preferences" not in tables and "alert_notifications" not in tables
        assert connection.execute("SELECT note FROM alert_reviews").fetchone()[0] == "preserve ✓"
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_interval_update_wakes_long_wait_without_overlapping_scans(tmp_path):
    store = EventStore(tmp_path)
    entered, release, second = (threading.Event() for _ in range(3))
    count = 0
    active = 0
    overlaps = []

    def collector(*args, **kwargs):
        nonlocal count, active
        active += 1
        overlaps.append(active)
        count += 1
        if count == 1:
            entered.set()
            assert release.wait(3)
        else:
            second.set()
        active -= 1
        return CollectionBatch([], [])

    monitor = LiveMonitor(store, interval=300, collector=collector)
    try:
        monitor.start()
        assert entered.wait(3)
        monitor.set_preferences(default_preferences() | {"scan_interval_seconds": 30})
        assert not monitor.scan()
        release.set()
        assert second.wait(3)
        assert max(overlaps) == 1
        assert monitor.state()["monitor"]["interval_seconds"] == 30
    finally:
        release.set()
        monitor.stop()
        store.close()


@pytest.fixture
def dashboard(tmp_path):
    store = EventStore(tmp_path)
    monitor = LiveMonitor(store, collector=lambda *a, **k: CollectionBatch([], []))
    server = DashboardServer(monitor, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        monitor.stop()
        store.close()


def request(server, body, *, headers=None):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        client.request("POST", "/api/preferences", body=body, headers=headers or {})
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def test_http_preferences_contract_and_guards(dashboard):
    headers = {"X-Sentinel-Token": dashboard.token, "Origin": dashboard.url}
    preferences = default_preferences() | {"scan_interval_seconds": 47}
    assert request(dashboard, json.dumps(preferences), headers=headers) == (
        200,
        {"preferences": preferences, "preferences_status": "ok"},
    )
    for guarded in (
        {},
        {"X-Sentinel-Token": "wrong"},
        headers | {"Host": "evil.example"},
        headers | {"Origin": "https://evil.example"},
    ):
        assert request(dashboard, None, headers=guarded)[0] == 403
    assert request(dashboard, None, headers=headers | {"Content-Length": "1025"}) == (
        400,
        {"error": "invalid_body"},
    )
    assert request(dashboard, None, headers=headers | {"Transfer-Encoding": "chunked"}) == (
        400,
        {"error": "invalid_body"},
    )


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"null",
        b"[]",
        b"{}",
        b"{",
        b'"text"',
        b"\xff",
        b'{"schema_version":1,"schema_version":1}',
        b"[" * 1000,
        json.dumps(default_preferences() | {"minimum_severity": "invalid"}).encode(),
        json.dumps(default_preferences() | {"scan_interval_seconds": True}).encode(),
    ],
)
def test_http_invalid_preferences_are_bounded_errors(dashboard, body):
    assert request(dashboard, body, headers={"X-Sentinel-Token": dashboard.token}) == (
        400,
        {"error": "invalid_preferences"},
    )
    assert dashboard.monitor.store.preferences()["preferences"] == default_preferences()


def test_cli_default_preserves_saved_interval(monkeypatch):
    calls = []
    monkeypatch.setattr(live, "serve", lambda *args: calls.append(args))
    assert cli.main(["serve"]) == 0
    assert calls[0][2] is None
    assert cli.main(["serve", "--interval", "47"]) == 0
    assert calls[1][2] == 47
