"""Persistent, local-only Windows monitoring and a loopback dashboard.

The HTTP endpoint is for one trusted workstation, never a network deployment.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
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
from .health import build_health
from .models import Event, ValidationError, format_timestamp, normalize
from .rules import load_rules
from .windows import collect_windows


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)


def _now() -> datetime:
    return datetime.now(UTC)


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
                self._db.executescript(
                    "CREATE TABLE IF NOT EXISTS events ("
                    "event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL);"
                    "CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);"
                    "CREATE TABLE IF NOT EXISTS alerts ("
                    "alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL,"
                    "evidence TEXT NOT NULL);"
                    "CREATE INDEX IF NOT EXISTS alerts_time ON alerts(timestamp);"
                )
        except BaseException:
            # The caller never receives this instance if initialization fails.
            self._db.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._db.close()

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

    def add_alert(self, alert: Alert) -> None:
        evidence = []
        with self._lock, self._db:
            for event_id in alert.event_ids:
                row = self._db.execute(
                    "SELECT payload FROM events WHERE event_id=?", (event_id,)
                ).fetchone()
                if row:
                    evidence.append(json.loads(row[0]))
            self._db.execute(
                "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?)",
                (
                    alert.alert_id,
                    format_timestamp(alert.timestamp),
                    _json(alert.to_dict()),
                    _json(evidence),
                ),
            )
            self._db.execute(
                "DELETE FROM alerts WHERE alert_id IN (SELECT alert_id FROM alerts "
                "ORDER BY timestamp DESC, alert_id DESC LIMIT -1 OFFSET ?)",
                (self.max_alerts,),
            )

    def evidence(self, alert_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT payload,evidence FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
            return {"alert": json.loads(row[0]), "events": json.loads(row[1])} if row else None

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
        interval: int = 15,
        lookback_hours: int = 24,
        collector: Callable = collect_windows,
    ):
        if not 5 <= interval <= 3600 or not 1 <= lookback_hours <= 168:
            raise ValidationError("Interval must be 5..3600 seconds and lookback 1..168 hours")
        self.store, self.interval, self.collector = store, interval, collector
        self.started_at = format_timestamp(_now())
        self._since = _now() - timedelta(hours=lookback_hours)
        self._lookback_hours = lookback_hours
        self._engine = RuleEngine(load_rules())
        self._watermark: datetime | None = None
        self._needs_rebuild = False
        self._rebuild_engine()
        self._status_lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._status = {
            "running": False,
            "stopped": False,
            "scanning": False,
            "interval_seconds": interval,
            "last_error": None,
            "late_events": 0,
            "last_attempt_at": None,
        }
        self._last_scan_at: str | None = None
        self._sources: list[dict] = []
        self._source_success: dict[str, str] = {}

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
                    self.store.add_alert(alert)
                self._watermark = event.timestamp
            self.store.prune_events()
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
                self.scan()
                self._stop.wait(self.interval)

        self._thread = threading.Thread(target=poll, daemon=True, name="sentinel-windows-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
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
        return {
            "version": __version__,
            "started_at": self.started_at,
            "last_scan_at": last_scan,
            "monitor": status,
            "sources": sources,
            "health": build_health(sources, status, last_scan),
            **self.store.snapshot(limit),
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
        if urlsplit(self.path).path != "/api/scan":
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
        if not 0 <= length <= 1024 or self.headers.get("Transfer-Encoding"):
            self._json_reply(400, {"error": "invalid_body"})
            return
        if length:
            self.rfile.read(length)
        started = self.server.monitor.request_scan()
        self._json_reply(202, {"status": "started" if started else "busy"})


def serve(
    data_dir: Path,
    port: int = 8765,
    interval: int = 15,
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
