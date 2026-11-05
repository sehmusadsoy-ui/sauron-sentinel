"""Native Windows host for the existing local monitoring application.

The native window exposes no Python API to JavaScript. Its data directory is
separate from source checkouts and portable executable bundles.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import importlib
import json
import os
import platform
import sys
import tempfile
import threading
import traceback
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import urlopen

from . import __version__
from .live import DashboardServer, EventStore, LiveMonitor
from .rules import load_rules
from .windows import CHANNELS, CollectionBatch


class AlreadyRunning(Exception):
    """Another desktop instance holds the selected data directory's lock."""


def default_data_dir() -> Path:
    """Choose per-user application storage, never the executable directory."""
    if platform.system() == "Windows":
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
    else:
        base = Path.home() / ".local" / "share"
    return base / "SauronSentinel"


class InstanceLock:
    """An OS-held file lock; stale files do not imply a running process.

    The one-byte lock file intentionally remains after release. Deleting a lock
    file can race with another process acquiring its existing file descriptor.
    """

    def __init__(self, directory: Path):
        self.path = Path(directory) / "desktop.lock"
        self._file = None

    def acquire(self) -> None:
        if self._file is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            handle.seek(0, 2)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK) or getattr(
                    exc, "winerror", None
                ) in (32, 33):
                    raise AlreadyRunning from exc
                raise
        except BaseException:
            handle.close()
            raise
        self._file = handle

    def release(self) -> None:
        if self._file is None:
            return
        handle, self._file = self._file, None
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


class DesktopRuntime:
    """Own the lock, database, monitor, and HTTP worker as one lifecycle."""

    def __init__(self, data_dir: Path, *, collector=None):
        self.data_dir = Path(data_dir)
        self.collector = collector
        self.lock = InstanceLock(self.data_dir)
        self.store: EventStore | None = None
        self.monitor: LiveMonitor | None = None
        self.server: DashboardServer | None = None
        self._http_thread: threading.Thread | None = None
        self._close_lock = threading.Lock()
        self._closed = False

    def start(self) -> str:
        if self._closed:
            raise RuntimeError("Desktop runtime has already closed")
        if self.server is not None:
            return self.server.url
        try:
            self.lock.acquire()
            self.store = EventStore(self.data_dir)
            options = {} if self.collector is None else {"collector": self.collector}
            self.monitor = LiveMonitor(self.store, **options)
            self.server = DashboardServer(self.monitor, port=0)
            self._http_thread = threading.Thread(
                target=lambda: self.server.serve_forever(poll_interval=0.1),
                name="sentinel-desktop-http",
                daemon=True,
            )
            self._http_thread.start()
            self.monitor.start()
            return self.server.url
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        """Release every acquired resource, including partial startup resources."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            if self.server is not None:
                if self._http_thread is not None and self._http_thread.is_alive():
                    with contextlib.suppress(Exception):
                        self.server.shutdown()
                    self._http_thread.join(timeout=5)
                with contextlib.suppress(Exception):
                    self.server.server_close()
            if self.monitor is not None:
                with contextlib.suppress(Exception):
                    self.monitor.stop()
            if self.store is not None:
                with contextlib.suppress(Exception):
                    self.store.close()
            with contextlib.suppress(Exception):
                self.lock.release()

    def __enter__(self) -> DesktopRuntime:
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _show_message(message: str, *, error: bool = True) -> None:
    """Show concise Turkish errors for a windowed executable without raw logs."""
    if platform.system() == "Windows" and (getattr(sys, "frozen", False) or sys.stderr is None):
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None, message, "Sauron Sentinel", 0x10 if error else 0x40
            )
            return
        except Exception:
            pass
    if sys.stderr is not None:
        print(f"Sauron Sentinel: {message}", file=sys.stderr)


def _same_origin(url: str, origin: str) -> bool:
    try:
        parsed, expected = urlsplit(url), urlsplit(origin)
        return (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port == expected.port
            and parsed.username is None
            and parsed.password is None
        )
    except (ValueError, TypeError):
        return False


def _protect_native_window(window, origin: str) -> None:
    """Use WebView2's cancellable events to block external document navigation."""
    browser = window.native.webview
    owner = window.native.browser
    attached = False

    def navigation_starting(_sender, args):
        if not _same_origin(str(args.Uri), origin):
            args.Cancel = True

    def new_window_requested(_sender, args):
        args.Handled = True

    def download_starting(sender, args):
        operation = getattr(args, "DownloadOperation", None)
        url = str(getattr(operation, "Uri", ""))
        if url != origin + "/api/export":
            args.Cancel = True
            return
        try:
            # Reuse the native Save As dialog only after the URL is verified.
            owner.on_download_starting(sender, args)
        except Exception:
            args.Cancel = True

    def attach_core(core):
        nonlocal attached
        if attached:
            return
        core.NewWindowRequested += new_window_requested
        # The library registers an unrestricted handler first. Replace it rather
        # than allowing its Save As dialog to run before our URL check.
        core.DownloadStarting -= owner.on_download_starting
        core.DownloadStarting += download_starting
        attached = True

    def initialized(sender, args):
        if args.IsSuccess:
            attach_core(sender.CoreWebView2)

    browser.NavigationStarting += navigation_starting
    browser.CoreWebView2InitializationCompleted += initialized
    if browser.CoreWebView2 is not None:
        attach_core(browser.CoreWebView2)


def _run_window(runtime: DesktopRuntime, webview) -> None:
    origin = runtime.start()
    webview.settings["ALLOW_DOWNLOADS"] = True
    webview.settings["ALLOW_FILE_URLS"] = False
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
    webview.settings["REMOTE_DEBUGGING_PORT"] = None
    window = webview.create_window(
        "Sauron Sentinel",
        url=origin,
        width=1280,
        height=850,
        min_size=(900, 650),
        background_color="#0b101b",
        text_select=True,
    )
    failed = []

    def renderer_selected(renderer):
        if renderer != "edgechromium":
            failed.append("unsupported_renderer")
            return False
        return None

    def before_show(window):
        try:
            _protect_native_window(window, origin)
        except Exception as exc:
            failed.append(exc)
            window.native.Close()

    window.events.initialized += renderer_selected
    window.events.before_show += before_show
    webview.start(
        gui="edgechromium",
        debug=False,
        private_mode=True,
        storage_path=str(runtime.data_dir / "webview"),
    )
    if failed:
        cause = failed[0] if isinstance(failed[0], Exception) else None
        raise RuntimeError("Required native renderer is unavailable") from cause


def _record_startup_error(runtime: DesktopRuntime) -> None:
    """Keep the last failure locally; this log is never part of a portable build."""
    runtime.close()
    with contextlib.suppress(OSError):
        runtime.data_dir.mkdir(parents=True, exist_ok=True)
        with (runtime.data_dir / "startup-error.log").open("w", encoding="utf-8") as stream:
            traceback.print_exc(file=stream)


def _verify_desktop_libraries() -> None:
    """Load the packaged .NET/WebView2 assemblies without opening a window."""
    backend = importlib.import_module("webview.platforms.edgechromium")
    if not hasattr(backend, "EdgeChrome"):
        raise RuntimeError("Desktop renderer library unavailable")


def _diagnose(output: Path) -> int:
    """Check a frozen bundle without a GUI or access to existing user telemetry."""
    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "version": __version__,
        "frozen": bool(getattr(sys, "frozen", False)),
        "checks": {},
        "collected_windows_events": False,
    }
    try:
        package = resources.files("sauron_sentinel")
        for name in ("defaults.toml", "demo.jsonl", "windows_collector.ps1"):
            if not package.joinpath(name).read_bytes():
                raise RuntimeError("Missing package resource")
        for name in ("index.html", "app.js", "styles.css"):
            if not package.joinpath("static", name).read_bytes():
                raise RuntimeError("Missing dashboard resource")
        report["checks"]["resources"] = True
        if not load_rules():
            raise RuntimeError("Missing rules")
        report["checks"]["rules"] = True
        if getattr(sys, "frozen", False) and platform.system() == "Windows":
            _verify_desktop_libraries()
            report["checks"]["desktop_libraries"] = True
        with tempfile.TemporaryDirectory(prefix="sauron-desktop-diagnose-") as directory:
            data_dir = Path(directory)
            lock = InstanceLock(data_dir)
            other = InstanceLock(data_dir)
            try:
                lock.acquire()
                try:
                    other.acquire()
                except AlreadyRunning:
                    report["checks"]["instance_lock"] = True
                else:
                    raise RuntimeError("Instance lock unavailable")
            finally:
                other.release()
                lock.release()

            def empty_collector(*_args, **_kwargs):
                return CollectionBatch(
                    [],
                    [
                        {"channel": channel, "status": "unavailable", "event_count": 0}
                        for channel in CHANNELS
                    ],
                )

            runtime = DesktopRuntime(data_dir, collector=empty_collector)
            try:
                origin = runtime.start()
                with urlopen(origin + "/", timeout=5) as response:
                    if response.status != 200 or not response.read():
                        raise RuntimeError("Dashboard unavailable")
                with urlopen(origin + "/api/state", timeout=5) as response:
                    state = json.load(response)
                    if state["summary"]["events_total"] != 0:
                        raise RuntimeError("Unexpected diagnostic data")
                report["checks"]["loopback_http"] = True
                if not (data_dir / "sentinel.db").is_file():
                    raise RuntimeError("SQLite unavailable")
                report["checks"]["sqlite"] = True
            finally:
                runtime.close()
            if runtime._http_thread is not None and runtime._http_thread.is_alive():
                raise RuntimeError("HTTP worker remained active")
            if runtime.monitor is not None and runtime.monitor._thread is not None:
                if runtime.monitor._thread.is_alive():
                    raise RuntimeError("Monitor remained active")
            lock.acquire()
            lock.release()
            report["checks"]["shutdown"] = True
        report["status"] = "ok"
    except Exception:
        report["error"] = "diagnostics_failed"
    try:
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        _show_message("Tanılama raporu kaydedilemedi. Farklı bir konum seçin.")
        return 1
    return 0 if report["status"] == "ok" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="SauronSentinel", description="Sauron Sentinel masaüstü")
    parser.add_argument("--data-dir", type=Path, help="Test için farklı veri klasörü")
    parser.add_argument(
        "--diagnose", type=Path, metavar="PATH", help="Paket tanılamasını JSON'a yaz"
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if args.diagnose is not None:
        return _diagnose(args.diagnose)
    if platform.system() != "Windows":
        _show_message("Masaüstü uygulaması Windows 10 veya 11 gerektirir.")
        return 1
    runtime = DesktopRuntime(args.data_dir if args.data_dir is not None else default_data_dir())
    try:
        webview = importlib.import_module("webview")
        _run_window(runtime, webview)
        return 0
    except AlreadyRunning:
        runtime.close()
        _show_message("Sauron Sentinel bu veri klasörü için zaten açık.", error=False)
        return 0
    except ImportError:
        _record_startup_error(runtime)
        _show_message("Masaüstü bileşenleri bulunamadı. Windows uygulama paketini yeniden kurun.")
        return 1
    except (Exception, KeyboardInterrupt, SystemExit):
        _record_startup_error(runtime)
        _show_message(
            "Uygulama başlatılamadı. Veri klasörünün erişilebilir olduğunu ve "
            "Microsoft Edge WebView2 Runtime'ın kurulu olduğunu kontrol edin."
        )
        return 1
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
