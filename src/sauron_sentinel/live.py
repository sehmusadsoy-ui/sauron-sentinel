"""Persistent, local-only Windows monitoring and a loopback dashboard.

The HTTP endpoint is for one trusted workstation, never a network deployment.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
import unicodedata
import webbrowser
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .engine import Alert, RuleEngine
from .explanations import explanation_for
from .health import build_health
from .models import Event, ValidationError, format_timestamp, normalize
from .preferences import SEVERITIES, default_preferences, validate_preferences
from .rules import load_rules
from .windows import collect_windows


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)


def _now() -> datetime:
    return datetime.now(UTC)


def _validate_review(status: Any, note: Any) -> None:
    if type(status) is not str or status not in {"new", "reviewed", "expected"}:
        raise ValidationError("Invalid alert review status")
    if type(note) is not str or len(note) > 500:
        raise ValidationError("Alert review note must be at most 500 characters")
    if any(
        character not in "\n\t" and unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in note
    ):
        raise ValidationError("Alert review note contains control characters")


def _review_object(row: tuple | None) -> dict:
    if row is None or row[0] is None:
        return {"status": "new", "note": "", "updated_at": None}
    return {"status": row[0], "note": row[1], "updated_at": row[2]}


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate JSON object key")
        result[key] = value
    return result


class EventStore:
    """Bounded SQLite storage with serialized access and immutable alert evidence."""

    def __init__(self, directory: Path, max_events: int = 20_000, max_alerts: int = 2000):
        if not 1 <= max_events <= 100_000 or not 1 <= max_alerts <= 10_000:
            raise ValidationError("Invalid local storage capacity")
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.max_events, self.max_alerts = max_events, max_alerts
        self._lock = threading.RLock()
        self._db = sqlite3.connect(directory / "sentinel.db", check_same_thread=False)
        try:
            with self._db:
                # Explicit BEGIN keeps DDL and the version marker in one transaction.
                # executescript would commit an existing transaction before running.
                self._db.execute("BEGIN IMMEDIATE")
                version = self._db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1, 2):
                    raise sqlite3.DatabaseError("Unsupported local storage schema version")
                if version == 0:
                    for statement in (
                        "CREATE TABLE IF NOT EXISTS events ("
                        "event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL)",
                        "CREATE INDEX IF NOT EXISTS events_time ON events(timestamp)",
                        "CREATE TABLE IF NOT EXISTS alerts ("
                        "alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL,"
                        "evidence TEXT NOT NULL)",
                        "CREATE INDEX IF NOT EXISTS alerts_time ON alerts(timestamp)",
                        "CREATE TABLE alert_reviews ("
                        "alert_id TEXT PRIMARY KEY, status TEXT NOT NULL "
                        "CHECK(status IN ('new','reviewed','expected')), "
                        "note TEXT NOT NULL, updated_at TEXT NOT NULL)",
                    ):
                        self._db.execute(statement)
                if version < 2:
                    for statement in (
                        "CREATE TABLE app_preferences (id INTEGER PRIMARY KEY CHECK(id=1),"
                        "payload TEXT NOT NULL)",
                        "CREATE TABLE alert_notifications (alert_id TEXT PRIMARY KEY,"
                        "unread INTEGER NOT NULL CHECK(unread IN (0,1)),"
                        "attempted_at TEXT,attempt_status TEXT)",
                        "CREATE TABLE notification_state (id INTEGER PRIMARY KEY CHECK(id=1),"
                        "last_attempt_at TEXT,last_attempt_status TEXT,last_error TEXT)",
                        "INSERT INTO alert_notifications(alert_id,unread) "
                        "SELECT alert_id,0 FROM alerts",
                        "INSERT INTO notification_state(id) VALUES(1)",
                        "PRAGMA user_version=2",
                    ):
                        self._db.execute(statement)
                    self._db.execute(
                        "INSERT INTO app_preferences VALUES(1,?)", (_json(default_preferences()),)
                    )
                self._db.execute(
                    "DELETE FROM alert_reviews WHERE alert_id NOT IN (SELECT alert_id FROM alerts)"
                )
                self._db.execute(
                    "DELETE FROM alert_notifications "
                    "WHERE alert_id NOT IN (SELECT alert_id FROM alerts)"
                )
                self._load_preferences()
        except BaseException:
            # The caller never receives this instance if initialization fails.
            self._db.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _load_preferences(self) -> None:
        self._preferences_status = "ok"
        row = self._db.execute("SELECT payload FROM app_preferences WHERE id=1").fetchone()
        try:
            if row is None:
                raise ValidationError("Missing preferences")
            self._preferences = validate_preferences(
                json.loads(row[0], object_pairs_hook=_unique_json_object)
            )
        except (ValueError, TypeError, RecursionError):
            self._preferences = default_preferences()
            self._preferences_status = "reset_invalid"
            self._db.execute(
                "INSERT INTO app_preferences VALUES(1,?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (_json(self._preferences),),
            )

    def preferences(self) -> dict:
        with self._lock:
            return {
                "preferences": dict(self._preferences),
                "preferences_status": self._preferences_status,
            }

    def set_preferences(self, value: Any) -> dict:
        preferences = validate_preferences(value)
        with self._lock:
            with self._db:
                self._db.execute(
                    "UPDATE app_preferences SET payload=? WHERE id=1", (_json(preferences),)
                )
            self._preferences = preferences
            self._preferences_status = "ok"
            return self.preferences()

    def _unread_count(self) -> int:
        return self._db.execute(
            "SELECT count(*) FROM alert_notifications WHERE unread=1"
        ).fetchone()[0]

    def mark_read(self, alert_id: str) -> dict | None:
        with self._lock, self._db:
            if not self._db.execute(
                "SELECT 1 FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone():
                return None
            self._db.execute(
                "UPDATE alert_notifications SET unread=0 WHERE alert_id=?", (alert_id,)
            )
            return {"unread": False, "unread_count": self._unread_count()}

    def claim_notification(self, alert_id: str, timestamp: str) -> bool:
        """Commit the claim before calling an external adapter; never retry this alert."""
        with self._lock, self._db:
            claimed = self._db.execute(
                "UPDATE alert_notifications SET attempted_at=?,attempt_status='attempting' "
                "WHERE alert_id=? AND attempted_at IS NULL",
                (timestamp, alert_id),
            ).rowcount
            if claimed:
                self._record_notification(timestamp, "attempting", None)
            return bool(claimed)

    def _record_notification(self, timestamp: str, status: str, error: str | None) -> None:
        self._db.execute(
            "UPDATE notification_state SET last_attempt_at=?,last_attempt_status=?,last_error=? "
            "WHERE id=1",
            (timestamp, status, error),
        )

    def record_notification(
        self, timestamp: str, status: str, error: str | None, alert_id: str | None = None
    ) -> None:
        with self._lock, self._db:
            self._record_notification(timestamp, status, error)
            if alert_id is not None:
                self._db.execute(
                    "UPDATE alert_notifications SET attempt_status=? WHERE alert_id=?",
                    (status, alert_id),
                )

    def notifications(self) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT last_attempt_at,last_attempt_status,last_error "
                "FROM notification_state WHERE id=1"
            ).fetchone()
            return {
                "unread_count": self._unread_count(),
                "last_attempt_at": row[0],
                "last_attempt_status": row[1],
                "last_error": row[2],
                "delivery_guaranteed": False,
            }

    def dashboard_snapshot(self, limit: int) -> dict:
        """Keep displayed flags, the total unread count, and preferences consistent."""
        with self._lock:
            return {
                **self.snapshot(limit),
                **self.preferences(),
                "notifications": self.notifications(),
            }

    def add_events(self, events: list[Event], *, prune: bool = True) -> list[Event]:
        fresh = []
        with self._lock, self._db:
            for event in events:
                if event.synthetic:
                    raise ValidationError("Live storage accepts only non-synthetic observations")
                cursor = self._db.execute(
                    "INSERT OR IGNORE INTO events VALUES(?,?,?)",
                    (event.event_id, format_timestamp(event.timestamp), _json(event.to_dict())),
                )
                if cursor.rowcount:
                    fresh.append(event)
            if prune:
                self.prune_events()
        return sorted(fresh, key=lambda event: (event.timestamp, event.event_id))

    def prune_events(self) -> None:
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM events WHERE event_id IN (SELECT event_id FROM events "
                "ORDER BY timestamp DESC, event_id DESC LIMIT -1 OFFSET ?)",
                (self.max_events,),
            )

    def engine_events(self) -> list[Event]:
        with self._lock:
            return [
                normalize(json.loads(row[0]))
                for row in self._db.execute(
                    "SELECT payload FROM events ORDER BY timestamp, event_id"
                )
            ]

    def add_alert(self, alert: Alert, *, unread: bool = False) -> bool:
        evidence = []
        with self._lock, self._db:
            for event_id in alert.event_ids:
                row = self._db.execute(
                    "SELECT payload FROM events WHERE event_id=?", (event_id,)
                ).fetchone()
                if row:
                    evidence.append(json.loads(row[0]))
            inserted = self._db.execute(
                "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?)",
                (
                    alert.alert_id,
                    format_timestamp(alert.timestamp),
                    _json(alert.to_dict()),
                    _json(evidence),
                ),
            ).rowcount
            if inserted:
                self._db.execute(
                    "INSERT INTO alert_notifications(alert_id,unread) VALUES(?,?)",
                    (alert.alert_id, int(unread)),
                )
            self._db.execute(
                "DELETE FROM alerts WHERE alert_id IN (SELECT alert_id FROM alerts "
                "ORDER BY timestamp DESC, alert_id DESC LIMIT -1 OFFSET ?)",
                (self.max_alerts,),
            )
            self._db.execute(
                "DELETE FROM alert_reviews WHERE alert_id NOT IN (SELECT alert_id FROM alerts)"
            )
            self._db.execute(
                "DELETE FROM alert_notifications WHERE alert_id NOT IN (SELECT alert_id FROM alerts)"
            )
            return bool(inserted)

    def set_review(self, alert_id: str, status: str, note: str) -> dict | None:
        """Record a human disposition for this alert only, without changing evidence."""
        _validate_review(status, note)
        with self._lock, self._db:
            if not self._db.execute(
                "SELECT 1 FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone():
                return None
            updated_at = format_timestamp(_now())
            self._db.execute(
                "INSERT INTO alert_reviews(alert_id,status,note,updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(alert_id) DO UPDATE SET "
                "status=excluded.status,note=excluded.note,updated_at=excluded.updated_at",
                (alert_id, status, note, updated_at),
            )
            return {"status": status, "note": note, "updated_at": updated_at}

    def evidence(self, alert_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT a.payload,a.evidence,r.status,r.note,r.updated_at,n.unread FROM alerts a "
                "LEFT JOIN alert_reviews r ON r.alert_id=a.alert_id "
                "LEFT JOIN alert_notifications n ON n.alert_id=a.alert_id WHERE a.alert_id=?",
                (alert_id,),
            ).fetchone()
            if row is None:
                return None
            alert = json.loads(row[0])
            return {
                "alert": alert,
                "events": json.loads(row[1]),
                "explanation": explanation_for(alert["rule_id"]),
                "review": _review_object(row[2:5]),
                "unread": bool(row[5]),
            }

    def snapshot(self, limit: int = 100) -> dict:
        cutoff = format_timestamp(_now() - timedelta(hours=24))
        with self._lock:
            summary = {}
            data = {}
            for table in ("events", "alerts"):
                # Table names are fixed internal literals, never request parameters.
                summary[f"{table}_total"] = self._db.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0]
                summary[f"{table}_24h"] = self._db.execute(
                    f"SELECT count(*) FROM {table} WHERE timestamp>=?", (cutoff,)
                ).fetchone()[0]
                data[table] = [
                    json.loads(row[0])
                    for row in self._db.execute(
                        f"SELECT payload FROM {table} ORDER BY timestamp DESC LIMIT ?", (limit,)
                    )
                ]
            reviews = {
                row[0]: _review_object(row[1:])
                for row in self._db.execute(
                    "SELECT alert_id,status,note,updated_at FROM alert_reviews"
                )
            }
            for alert in data["alerts"]:
                alert["review"] = reviews.get(alert["alert_id"], _review_object(None))
            unread = {
                row[0]
                for row in self._db.execute(
                    "SELECT alert_id FROM alert_notifications WHERE unread=1"
                )
            }
            for alert in data["alerts"]:
                alert["unread"] = alert["alert_id"] in unread
            history = [
                {"hour": row[0] + ":00:00Z", "count": row[1]}
                for row in self._db.execute(
                    "SELECT substr(timestamp,1,13),count(*) FROM events "
                    "WHERE timestamp>=? GROUP BY substr(timestamp,1,13) ORDER BY 1",
                    (cutoff,),
                )
            ]
        return {"summary": summary, "history": history, **data}


class LiveMonitor:
    """Poll without changing audit policy, privileges, or Windows configuration."""

    def __init__(
        self,
        store: EventStore,
        interval: int | None = None,
        lookback_hours: int = 24,
        collector: Callable = collect_windows,
        notifier: Any = None,
    ):
        if (
            (interval is not None and (type(interval) is not int or not 5 <= interval <= 3600))
            or type(lookback_hours) is not int
            or not 1 <= lookback_hours <= 168
        ):
            raise ValidationError("Interval must be 5..3600 seconds and lookback 1..168 hours")
        self.store, self.collector, self.notifier = store, collector, notifier
        if interval is not None:
            preferences = store.preferences()["preferences"]
            preferences["scan_interval_seconds"] = interval
            store.set_preferences(preferences)
        self.interval = store.preferences()["preferences"]["scan_interval_seconds"]
        self._session_start = _now()
        self.started_at = format_timestamp(self._session_start)
        self._since = self._session_start - timedelta(hours=lookback_hours)
        self._lookback_hours = lookback_hours
        self._engine = RuleEngine(load_rules())
        self._watermark: datetime | None = None
        self._needs_rebuild = False
        self._baseline_pending = True
        self._rebuild_engine()
        self._status_lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._status = {
            "running": False,
            "stopped": False,
            "scanning": False,
            "interval_seconds": self.interval,
            "last_error": None,
            "late_events": 0,
            "last_attempt_at": None,
        }
        self._last_scan_at: str | None = None
        self._sources: list[dict] = []
        self._source_success: dict[str, str] = {}
        self._notification_error: str | None = None

    def set_preferences(self, value: Any) -> dict:
        # Serialize preference application and wakeup to avoid losing an update.
        with self._status_lock:
            result = self.store.set_preferences(value)
            self.interval = result["preferences"]["scan_interval_seconds"]
            self._status["interval_seconds"] = self.interval
            self._wake.set()
            return result

    def _native_status(self) -> dict:
        if self.notifier is None:
            return {"available": False, "last_error": "native_unavailable"}
        try:
            result = self.notifier.snapshot()
            available = type(result) is dict and result.get("available") is True
            error = result.get("last_error") if type(result) is dict else "native_unavailable"
            if error not in {
                None,
                "unsupported_platform",
                "not_initialized",
                "native_unavailable",
                "notification_failed",
            }:
                error = "notification_failed"
            return {"available": available, "last_error": error}
        except Exception:
            return {"available": False, "last_error": "native_unavailable"}

    def _notify(self, *, alert_id: str | None = None, test: bool = False) -> bool:
        timestamp = format_timestamp(_now())
        try:
            if alert_id is not None:
                if not self.store.claim_notification(alert_id, timestamp):
                    return False
            else:
                self.store.record_notification(timestamp, "attempting", None)
        except (sqlite3.Error, OSError):
            # Delivery requires a durable claim, but its failure must not abort detection.
            with self._status_lock:
                self._notification_error = "notification_failed"
            return False
        try:
            queued = self.notifier.notify(test=test) is True
        except Exception:
            queued = False
        metadata_error = None
        try:
            self.store.record_notification(
                timestamp,
                "queued" if queued else "failed",
                None if queued else "notification_failed",
                alert_id,
            )
        except (sqlite3.Error, OSError):
            # Keep the committed claim; uncertain status must never cause a retry.
            metadata_error = "notification_failed"
        with self._status_lock:
            self._notification_error = metadata_error
        return queued

    def test_notification(self) -> tuple[int, dict]:
        if not self.store.preferences()["preferences"]["notifications_enabled"]:
            return 409, {"error": "notifications_disabled"}
        if not self._native_status()["available"]:
            return 503, {"error": "notifications_unavailable"}
        if not self._notify(test=True):
            return 503, {"error": "notification_failed"}
        return 202, {"status": "queued"}

    def _accept_alert(self, alert: Alert) -> None:
        # An initial batch establishes the baseline even when some channels are denied.
        live = not self._baseline_pending and alert.timestamp >= self._session_start
        inserted = self.store.add_alert(alert, unread=True) if live else self.store.add_alert(alert)
        if not inserted or not live:
            return
        preferences = self.store.preferences()["preferences"]
        if (
            preferences["notifications_enabled"]
            and SEVERITIES.get(alert.severity, -1) >= SEVERITIES[preferences["minimum_severity"]]
            and self._native_status()["available"]
        ):
            self._notify(alert_id=alert.alert_id)

    def _rebuild_engine(self) -> None:
        self._engine = RuleEngine(load_rules())
        self._watermark = None
        for event in self.store.engine_events():
            for alert in self._engine.process(event):
                self.store.add_alert(alert)
            self._watermark = event.timestamp
        self._needs_rebuild = False

    def scan(self) -> bool:
        if self._stop.is_set():
            return False
        if not self._scan_lock.acquire(blocking=False):
            return False
        if self._stop.is_set():
            self._scan_lock.release()
            return False
        scan_start = _now()
        with self._status_lock:
            self._status["scanning"] = True
            self._status["last_attempt_at"] = format_timestamp(scan_start)
        try:
            if self._needs_rebuild:
                self._rebuild_engine()
            batch = self.collector(self._since, limit=200)
            # Keep this batch until alert evidence has been snapshotted.
            fresh = self.store.add_events(batch.events, prune=False)
            late = 0
            for event in fresh:
                if self._watermark is not None and event.timestamp < self._watermark:
                    late += 1
                    continue
                for alert in self._engine.process(event):
                    self._accept_alert(alert)
                self._watermark = event.timestamp
            self.store.prune_events()
            self._baseline_pending = False
            with self._status_lock:
                completed_at = format_timestamp(_now())
                sources = []
                for source in batch.sources:
                    channel = source["channel"]
                    if source["status"] == "ok":
                        self._source_success[channel] = completed_at
                    sources.append({**source, "last_success_at": self._source_success.get(channel)})
                self._sources = sources
                self._last_scan_at = format_timestamp(scan_start)
                self._status["last_error"] = None
                self._status["late_events"] += late
            # Read an overlap to catch commit delays; identity suppresses repeats.
            if batch.sources and all(source["status"] == "ok" for source in batch.sources):
                self._since = scan_start - timedelta(seconds=120)
            else:
                # Retry inaccessible channels over a bounded history when they recover.
                self._since = scan_start - timedelta(hours=self._lookback_hours)
            return True
        except Exception:
            # Keep raw Windows payloads and filesystem details out of browser errors.
            with self._status_lock:
                self._status["last_error"] = "collection_failed"
            self._needs_rebuild = True
            return False
        finally:
            with self._status_lock:
                self._status["scanning"] = False
            self._scan_lock.release()

    def request_scan(self) -> bool:
        if self._stop.is_set():
            return False
        with self._status_lock:
            if self._status["scanning"]:
                return False
        threading.Thread(target=self.scan, daemon=True, name="sentinel-manual-scan").start()
        return True

    def start(self) -> None:
        if self._thread is not None:
            return
        with self._status_lock:
            self._status["running"] = True

        def poll():
            while not self._stop.is_set():
                self._wake.clear()
                self.scan()
                self._wake.wait(self.interval)

        self._thread = threading.Thread(target=poll, daemon=True, name="sentinel-windows-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=35)
        # Also wait for a user-requested scan before its database is closed.
        with self._scan_lock, self._status_lock:
            self._status["running"] = False
            self._status["stopped"] = True

    def state(self, limit: int = 100) -> dict:
        with self._status_lock:
            status = dict(self._status)
            sources = [dict(source) for source in self._sources]
            last_scan = self._last_scan_at
            notification_error = self._notification_error
        snapshot = self.store.dashboard_snapshot(limit)
        notification_status = snapshot["notifications"]
        native_status = self._native_status()
        notification_status["available"] = native_status["available"]
        notification_status["last_error"] = (
            native_status["last_error"] or notification_error or notification_status["last_error"]
        )
        return {
            "version": __version__,
            "started_at": self.started_at,
            "last_scan_at": last_scan,
            "monitor": status,
            "sources": sources,
            "health": build_health(sources, status, last_scan),
            **snapshot,
        }


class DashboardServer(ThreadingHTTPServer):
    """Bind exclusively to IPv4 loopback, with origin/host and mutation protection."""

    daemon_threads = False
    allow_reuse_address = False

    def __init__(self, monitor: LiveMonitor, port: int = 8765):
        if type(port) is not int or not 0 <= port <= 65_535:
            raise ValidationError("Port must be an integer in 0..65535")
        self.monitor = monitor
        self.token = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", port), DashboardHandler)
        self.url = f"http://127.0.0.1:{self.server_port}"
        self.hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}
        self.origins = {"http://" + host for host in self.hosts}


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "SauronSentinel"
    sys_version = ""

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, *_):
        pass

    def _reply(self, code: int, data: bytes, content_type: str, *, download: bool = False):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; "
            "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        if download:
            self.send_header("Content-Disposition", 'attachment; filename="sentinel-export.json"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json_reply(self, code: int, data: Any, *, download: bool = False):
        self._reply(
            code, _json(data).encode("utf-8"), "application/json; charset=utf-8", download=download
        )

    def _allowed(self) -> bool:
        if self.headers.get("Host") not in self.server.hosts:
            self._json_reply(403, {"error": "host_not_allowed"})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.origins:
            self._json_reply(403, {"error": "origin_not_allowed"})
            return False
        return True

    def do_GET(self):
        if not self._allowed():
            return
        path = urlsplit(self.path).path
        if path == "/api/state":
            self._json_reply(200, self.server.monitor.state())
        elif path == "/api/export":
            self._json_reply(200, self.server.monitor.state(10_000), download=True)
        elif re.fullmatch(r"/api/alerts/[a-f0-9]{64}/evidence", path):
            result = self.server.monitor.store.evidence(path.split("/")[3])
            self._json_reply(200 if result else 404, result or {"error": "not_found"})
        elif path in ("/", "/index.html", "/app.js", "/styles.css"):
            name = "index.html" if path in ("/", "/index.html") else path[1:]
            payload = resources.files("sauron_sentinel").joinpath("static", name).read_bytes()
            if name == "index.html":
                payload = payload.replace(b"__SENTINEL_TOKEN__", self.server.token.encode("ascii"))
            mime = {
                "index.html": "text/html",
                "app.js": "text/javascript",
                "styles.css": "text/css",
            }[name]
            self._reply(200, payload, mime + "; charset=utf-8")
        else:
            self._json_reply(404, {"error": "not_found"})

    def do_POST(self):
        if not self._allowed():
            return
        path = urlsplit(self.path).path
        review_match = re.fullmatch(r"/api/alerts/([a-f0-9]{64})/review", path)
        read_match = re.fullmatch(r"/api/alerts/([a-f0-9]{64})/read", path)
        preferences_route = path == "/api/preferences"
        test_route = path == "/api/notifications/test"
        if not (
            path == "/api/scan" or review_match or read_match or preferences_route or test_route
        ):
            self._json_reply(404, {"error": "not_found"})
            return
        token = self.headers.get("X-Sentinel-Token", "")
        if not token.isascii() or not secrets.compare_digest(token, self.server.token):
            self._json_reply(403, {"error": "token_required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        body_limit = 8192 if review_match else 1024
        if (
            not 0 <= length <= body_limit
            or self.headers.get("Transfer-Encoding")
            or len(self.headers.get_all("Content-Length", [])) > 1
        ):
            self._json_reply(400, {"error": "invalid_body"})
            return
        body = self.rfile.read(length) if length else b""
        if review_match:
            try:
                payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object)
                if type(payload) is not dict or set(payload) != {"status", "note"}:
                    raise ValidationError("Review requires exactly status and note")
                result = self.server.monitor.store.set_review(
                    review_match[1], payload["status"], payload["note"]
                )
            except (UnicodeDecodeError, ValueError, RecursionError):
                self._json_reply(400, {"error": "invalid_review"})
                return
            self._json_reply(
                200 if result else 404, {"review": result} if result else {"error": "not_found"}
            )
            return
        if preferences_route or read_match or test_route:
            error = "invalid_preferences" if preferences_route else "invalid_body"
            try:
                payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object)
                if preferences_route:
                    result = self.server.monitor.set_preferences(payload)
                elif type(payload) is not dict or payload:
                    raise ValidationError("An empty object is required")
                elif read_match:
                    result = self.server.monitor.store.mark_read(read_match[1])
                else:
                    status, result = self.server.monitor.test_notification()
                    self._json_reply(status, result)
                    return
            except (UnicodeDecodeError, ValueError, RecursionError):
                self._json_reply(400, {"error": error})
                return
            self._json_reply(200 if result is not None else 404, result or {"error": "not_found"})
            return
        started = self.server.monitor.request_scan()
        self._json_reply(202, {"status": "started" if started else "busy"})


def serve(
    data_dir: Path,
    port: int = 8765,
    interval: int | None = None,
    lookback_hours: int = 24,
    open_browser: bool = False,
) -> None:
    store = EventStore(data_dir)
    monitor = None
    server = None
    try:
        monitor = LiveMonitor(store, interval, lookback_hours)
        server = DashboardServer(monitor, port)
        monitor.start()
        print(f"Sauron Sentinel {__version__}: {server.url}", flush=True)
        print("Local Windows monitoring. Keep this window open. Stop with Ctrl+C.", flush=True)
        if open_browser:
            webbrowser.open(server.url)
        server.serve_forever(poll_interval=0.5)
    finally:
        if server:
            server.server_close()
        if monitor:
            monitor.stop()
        store.close()
