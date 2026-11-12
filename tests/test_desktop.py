"""Native hosting lifecycle and safety, without requiring an actual GUI."""

from __future__ import annotations

import errno
import json
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.request import urlopen

import pytest

from sauron_sentinel import desktop
from sauron_sentinel.windows import CollectionBatch


def _empty_collector(*args, **kwargs):
    return CollectionBatch([], [])


class EventHook:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, callback):
        self.handlers.append(callback)
        return self

    def __isub__(self, callback):
        if callback in self.handlers:
            self.handlers.remove(callback)
        return self

    def fire(self, *args):
        return [callback(*args) for callback in self.handlers]


class FakeWebview:
    def __init__(self, *, renderer="edgechromium", failure=None):
        self.settings = {}
        self.renderer = renderer
        self.failure = failure
        self.created = None
        self.started = None
        self.downloads = []
        owner = SimpleNamespace(
            on_download_starting=lambda sender, args: self.downloads.append(args)
        )
        core = SimpleNamespace(NewWindowRequested=EventHook(), DownloadStarting=EventHook())
        core.DownloadStarting += owner.on_download_starting
        browser = SimpleNamespace(
            NavigationStarting=EventHook(),
            CoreWebView2InitializationCompleted=EventHook(),
            CoreWebView2=core,
        )
        self.window = SimpleNamespace(
            events=SimpleNamespace(initialized=EventHook(), before_show=EventHook()),
            native=SimpleNamespace(webview=browser, browser=owner, Close=lambda: None),
        )

    def create_window(self, title, **kwargs):
        self.created = (title, kwargs)
        return self.window

    def start(self, **kwargs):
        self.started = kwargs
        self.window.events.initialized.fire(self.renderer)
        self.window.events.before_show.fire(self.window)
        if self.failure:
            raise self.failure


class FakeNotifier:
    def __init__(self):
        self.bound = []
        self.closed = False

    def snapshot(self):
        return {"available": False, "last_error": "not_initialized"}

    def bind(self, window):
        self.bound.append(window)

    def close(self):
        self.closed = True


class FakeRuntime:
    def __init__(self, directory):
        self.data_dir = Path(directory)
        self.closed = False
        self.started = False
        self.notifier = FakeNotifier()

    def start(self):
        self.started = True
        return "http://127.0.0.1:12345"

    def close(self):
        self.closed = True
        self.notifier.close()


@pytest.fixture
def bundled_pythonnet(tmp_path, monkeypatch):
    bundle = tmp_path / "private bundle"
    dll = bundle / "pythonnet" / "runtime" / "Python.Runtime.dll"
    dll.parent.mkdir(parents=True)
    dll.touch()
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop.sys, "frozen", True, raising=False)
    monkeypatch.setattr(desktop.sys, "_MEIPASS", str(bundle), raising=False)
    return dll


def _pythonnet_loader_error(dll):
    return RuntimeError(f"Failed to resolve Python.Runtime.Loader.Initialize from {dll}")


def test_default_windows_data_is_per_user_not_source_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert desktop.default_data_dir() == tmp_path / "Local" / "SauronSentinel"
    monkeypatch.delenv("LOCALAPPDATA")
    monkeypatch.setattr(desktop.Path, "home", lambda: tmp_path)
    assert desktop.default_data_dir() == tmp_path / "AppData" / "Local" / "SauronSentinel"


def test_non_windows_data_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop.platform, "system", lambda: "Linux")
    monkeypatch.setattr(desktop.Path, "home", lambda: tmp_path)
    assert desktop.default_data_dir() == tmp_path / ".local" / "share" / "SauronSentinel"


def test_instance_lock_released_and_stale_file_is_harmless(tmp_path):
    first, second = desktop.InstanceLock(tmp_path), desktop.InstanceLock(tmp_path)
    try:
        first.acquire()
        first.acquire()
        with pytest.raises(desktop.AlreadyRunning):
            second.acquire()
    finally:
        first.release()
        first.release()
    assert first.path.is_file()
    second.acquire()
    second.release()


def test_os_lock_released_when_owning_process_exits(tmp_path):
    script = (
        "from pathlib import Path; import sys; "
        "from sauron_sentinel.desktop import InstanceLock; "
        "lock=InstanceLock(Path(sys.argv[1])); lock.acquire(); "
        "print('ready',flush=True); sys.stdin.read(1)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    other = desktop.InstanceLock(tmp_path)
    try:
        assert process.stdout.readline().strip() == "ready"
        with pytest.raises(desktop.AlreadyRunning):
            other.acquire()
        process.stdin.close()
        assert process.wait(timeout=5) == 0
        other.acquire()
    finally:
        other.release()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def test_runtime_dynamic_loopback_and_clean_close(tmp_path):
    notifier = FakeNotifier()
    runtime = desktop.DesktopRuntime(tmp_path, collector=_empty_collector, notifier=notifier)
    try:
        origin = runtime.start()
        assert origin.startswith("http://127.0.0.1:")
        assert runtime.server.server_port > 0
        with urlopen(origin + "/api/state", timeout=3) as response:
            assert json.load(response)["summary"]["events_total"] == 0
        assert runtime.start() == origin
        monitor_thread = runtime.monitor._thread
    finally:
        runtime.close()
        runtime.close()
    assert not runtime._http_thread.is_alive()
    assert not monitor_thread.is_alive()
    assert notifier.closed
    replacement = desktop.InstanceLock(tmp_path)
    replacement.acquire()
    replacement.release()
    with pytest.raises(RuntimeError, match="already closed"):
        runtime.start()


def test_runtime_second_instance_cannot_start_monitor(tmp_path):
    first = desktop.DesktopRuntime(tmp_path, collector=_empty_collector)
    second = desktop.DesktopRuntime(tmp_path, collector=_empty_collector)
    try:
        first.start()
        with pytest.raises(desktop.AlreadyRunning):
            second.start()
        assert second.store is None
        assert second.monitor is None
        assert first._http_thread.is_alive()
    finally:
        second.close()
        first.close()


@pytest.mark.parametrize("failure_at", ["store", "monitor", "server", "monitor_start"])
def test_partial_startup_always_releases_resources(tmp_path, monkeypatch, failure_at):
    closed = []
    notifier = FakeNotifier()

    class Store:
        def __init__(self, path):
            if failure_at == "store":
                raise OSError("private failure")

        def close(self):
            closed.append("store")

    class Monitor:
        def __init__(self, store, **kwargs):
            assert kwargs["notifier"] is notifier
            if failure_at == "monitor":
                raise OSError("private failure")

        def start(self):
            if failure_at == "monitor_start":
                raise OSError("private failure")

        def stop(self):
            closed.append("monitor")

    class Server:
        url = "http://127.0.0.1:12345"

        def __init__(self, monitor, port):
            self.stop = threading.Event()
            if failure_at == "server":
                raise OSError("private failure")

        def serve_forever(self, **kwargs):
            self.stop.wait(5)

        def shutdown(self):
            self.stop.set()

        def server_close(self):
            closed.append("server")

    monkeypatch.setattr(desktop, "EventStore", Store)
    monkeypatch.setattr(desktop, "LiveMonitor", Monitor)
    monkeypatch.setattr(desktop, "DashboardServer", Server)
    runtime = desktop.DesktopRuntime(tmp_path, notifier=notifier)
    with pytest.raises(OSError):
        runtime.start()
    assert notifier.closed
    if failure_at != "store":
        assert "store" in closed
    if failure_at in ("server", "monitor_start"):
        assert "monitor" in closed
    if failure_at == "monitor_start":
        assert "server" in closed
        assert not runtime._http_thread.is_alive()
    probe = desktop.InstanceLock(tmp_path)
    probe.acquire()
    probe.release()


def test_native_window_has_no_api_bridge_and_forces_modern_renderer(tmp_path):
    runtime = FakeRuntime(tmp_path)
    webview = FakeWebview()
    desktop._run_window(runtime, webview)
    title, options = webview.created
    assert title == "Sauron Sentinel"
    assert options["width"] == 1280 and options["height"] == 850
    assert options["min_size"] == (900, 650)
    assert "js_api" not in options
    assert webview.started == {
        "gui": "edgechromium",
        "debug": False,
        "private_mode": True,
        "storage_path": str(tmp_path / "webview"),
    }
    assert webview.settings["ALLOW_FILE_URLS"] is False
    assert webview.settings["ALLOW_DOWNLOADS"] is True
    assert webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] is False
    assert webview.settings["REMOTE_DEBUGGING_PORT"] is None
    assert runtime.notifier.bound == [webview.window]


def test_legacy_renderer_refused(tmp_path):
    with pytest.raises(RuntimeError, match="renderer"):
        desktop._run_window(FakeRuntime(tmp_path), FakeWebview(renderer="mshtml"))


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "file:///secret",
        "data:text/html,evil",
        "javascript:alert(1)",
        "http://127.0.0.1:1/",
        "http://127.0.0.1:12345@evil.test",
        "http://[broken",
    ],
)
def test_native_external_navigation_canceled(tmp_path, url):
    webview = FakeWebview()
    desktop._run_window(FakeRuntime(tmp_path), webview)
    args = SimpleNamespace(Uri=url, Cancel=False)
    webview.window.native.webview.NavigationStarting.fire(None, args)
    assert args.Cancel is True


def test_native_local_navigation_allowed_and_new_windows_downloads_blocked(tmp_path):
    webview = FakeWebview()
    desktop._run_window(FakeRuntime(tmp_path), webview)
    browser = webview.window.native.webview
    args = SimpleNamespace(Uri="http://127.0.0.1:12345/#main", Cancel=False)
    browser.NavigationStarting.fire(None, args)
    assert args.Cancel is False
    new = SimpleNamespace(Handled=False)
    browser.CoreWebView2.NewWindowRequested.fire(None, new)
    assert new.Handled is True
    download = SimpleNamespace(Cancel=False)
    browser.CoreWebView2.DownloadStarting.fire(None, download)
    assert download.Cancel is True


def test_core_guards_attached_after_async_initialization(tmp_path):
    webview = FakeWebview()
    browser = webview.window.native.webview
    core, browser.CoreWebView2 = browser.CoreWebView2, None
    desktop._run_window(FakeRuntime(tmp_path), webview)
    browser.CoreWebView2 = core
    browser.CoreWebView2InitializationCompleted.fire(browser, SimpleNamespace(IsSuccess=True))
    assert core.NewWindowRequested.handlers and core.DownloadStarting.handlers


def test_main_runtime_closed_when_gui_fails_without_leaking_error(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    messages = []
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop, "DesktopRuntime", lambda path: runtime)
    monkeypatch.setattr(
        desktop.importlib,
        "import_module",
        lambda name: FakeWebview(failure=RuntimeError("private")),
    )
    monkeypatch.setattr(
        desktop, "_show_message", lambda message, **kwargs: messages.append(message)
    )
    assert desktop.main(["--data-dir", str(tmp_path)]) == 1
    assert runtime.closed
    assert messages and "private" not in messages[0]


def test_main_existing_instance_is_informational_and_successful(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    messages = []

    def busy():
        raise desktop.AlreadyRunning

    runtime.start = busy
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop, "DesktopRuntime", lambda path: runtime)
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: FakeWebview())
    monkeypatch.setattr(desktop, "_show_message", lambda message, **kwargs: messages.append(kwargs))
    assert desktop.main(["--data-dir", str(tmp_path)]) == 0
    assert messages == [{"error": False}]
    assert runtime.closed


def test_headless_diagnosis_checks_bundle_without_gui_or_real_collector(tmp_path, monkeypatch):
    real_import = desktop.importlib.import_module

    def no_gui(name, package=None):
        if name == "webview":
            raise AssertionError("GUI must not import during diagnostics")
        return real_import(name, package)

    monkeypatch.setattr(desktop.importlib, "import_module", no_gui)
    report_path = tmp_path / "report.json"
    assert desktop.main(["--diagnose", str(report_path)]) == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["collected_windows_events"] is False
    assert report["checks"] == {
        "resources": True,
        "rules": True,
        "sqlite": True,
        "loopback_http": True,
        "instance_lock": True,
        "shutdown": True,
    }
    assert "data_dir" not in report and "events" not in report


def test_diagnosis_failure_is_generic_report(tmp_path, monkeypatch):
    def missing(name):
        raise OSError("private installation path")

    monkeypatch.setattr(desktop.resources, "files", missing)
    report_path = tmp_path / "report.json"
    assert desktop.main(["--diagnose", str(report_path)]) == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["error"] == "diagnostics_failed"
    assert "private installation path" not in report_path.read_text(encoding="utf-8")


def test_diagnosis_reports_bundled_pythonnet_download_block_without_paths(
    bundled_pythonnet, tmp_path, monkeypatch
):
    Path(f"{bundled_pythonnet}:Zone.Identifier").write_bytes(
        b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/private-download\r\n"
    )

    def fail():
        raise RuntimeError("private wrapper") from _pythonnet_loader_error(bundled_pythonnet)

    monkeypatch.setattr(desktop, "_verify_desktop_libraries", fail)
    report_path = tmp_path / "report.json"
    assert desktop.main(["--diagnose", str(report_path)]) == 1
    contents = report_path.read_text(encoding="utf-8")
    report = json.loads(contents)
    assert report["status"] == "failed"
    assert report["error"] == "pythonnet_download_blocked"
    assert report["checks"] == {"resources": True, "rules": True}
    assert "private" not in contents


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:12345/api/export",
        "http://127.0.0.1:12345/api/export?other=1",
        "http://127.0.0.1:12345/api/export#fragment",
        "http://127.0.0.1:12345/other",
        "https://example.com/api/export",
        "file:///private.json",
    ],
)
def test_native_export_is_scoped_before_save_dialog(tmp_path, url):
    webview = FakeWebview()
    desktop._run_window(FakeRuntime(tmp_path), webview)
    args = SimpleNamespace(DownloadOperation=SimpleNamespace(Uri=url), Cancel=False)
    core = webview.window.native.webview.CoreWebView2
    core.DownloadStarting.fire(None, args)
    allowed = url == "http://127.0.0.1:12345/api/export"
    assert args.Cancel is (not allowed)
    assert len(webview.downloads) == int(allowed)
    assert len(core.DownloadStarting.handlers) == 1


def test_desktop_library_check_imports_native_backend_without_window(monkeypatch):
    imported = []

    def load(name):
        imported.append(name)
        return SimpleNamespace(EdgeChrome=object)

    monkeypatch.setattr(desktop.importlib, "import_module", load)
    desktop._verify_desktop_libraries()
    assert imported == ["webview.platforms.edgechromium"]
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: SimpleNamespace())
    with pytest.raises(RuntimeError, match="renderer library"):
        desktop._verify_desktop_libraries()


def test_startup_error_stops_monitor_before_showing_dialog(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop, "DesktopRuntime", lambda path: runtime)
    monkeypatch.setattr(
        desktop.importlib,
        "import_module",
        lambda name: FakeWebview(failure=RuntimeError("private failure")),
    )

    def show(message, **kwargs):
        assert runtime.closed
        assert "private failure" not in message

    monkeypatch.setattr(desktop, "_show_message", show)
    assert desktop.main(["--data-dir", str(tmp_path)]) == 1
    assert "private failure" in (tmp_path / "startup-error.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("marked", [True, False])
def test_startup_pythonnet_download_block_requires_marker(
    bundled_pythonnet, tmp_path, monkeypatch, marked
):
    marker = Path(f"{bundled_pythonnet}:Zone.Identifier")
    if marked:
        marker.write_bytes(b"[ZoneTransfer]\r\nZoneId=3\r\n")
    runtime = FakeRuntime(tmp_path)
    messages, probes = [], []

    def fail(*args):
        try:
            raise _pythonnet_loader_error(bundled_pythonnet)
        except RuntimeError:
            # pywebview's retry leaves an implicit exception context.
            raise ImportError("private retry failure")  # noqa: B904

    def probe():
        probes.append(True)
        return "unknown"

    monkeypatch.setattr(desktop, "DesktopRuntime", lambda path: runtime)
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: FakeWebview())
    monkeypatch.setattr(desktop, "_run_window", fail)
    monkeypatch.setattr(desktop, "_webview2_runtime_status", probe)
    monkeypatch.setattr(desktop, "_show_message", messages.append)
    assert desktop.main(["--data-dir", str(tmp_path)]) == 1
    assert runtime.closed
    expected = "pythonnet_download_blocked" if marked else "components"
    assert messages == [desktop._STARTUP_MESSAGES[expected]]
    assert "private" not in messages[0]
    assert probes == ([] if marked else [True])
    assert marker.exists() == marked
    log = (tmp_path / "startup-error.log").read_text(encoding="utf-8")
    assert str(bundled_pythonnet) in log and "private retry failure" in log


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        (b"[ZoneTransfer]\r\nZoneId=4\r\n", True),
        (b"[ZoneTransfer]\r\nZoneId=2\r\n", False),
        (b"[ZoneTransfer]\r\nZoneId=30\r\n", False),
        (b"[OtherSection]\r\nZoneId=3\r\n", False),
        (b"[ZoneTransfer]\r\nZoneId=3\r\nZoneId=2\r\n", False),
        (b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=" + b"x" * 4096, False),
    ],
)
def test_bundled_pythonnet_download_block_requires_internet_or_restricted_zone(
    bundled_pythonnet, marker, expected
):
    Path(f"{bundled_pythonnet}:Zone.Identifier").write_bytes(marker)
    error = _pythonnet_loader_error(bundled_pythonnet)
    assert desktop._pythonnet_download_blocked(error) is expected


def test_bundled_pythonnet_marker_is_ignored_for_unrelated_load_errors(bundled_pythonnet, tmp_path):
    marked = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    Path(f"{bundled_pythonnet}:Zone.Identifier").write_bytes(marked)
    other_dll = tmp_path / "Python.Runtime.dll"
    other_dll.touch()
    Path(f"{other_dll}:Zone.Identifier").write_bytes(marked)
    assert not desktop._pythonnet_download_blocked(_pythonnet_loader_error(other_dll))
    assert not desktop._pythonnet_download_blocked(RuntimeError(str(bundled_pythonnet)))


@pytest.mark.parametrize(
    ("error", "stage", "runtime_status", "expected"),
    [
        (ModuleNotFoundError("private module"), "components", "unknown", "components"),
        (ModuleNotFoundError("private module"), "window", "missing", "components"),
        (FileNotFoundError("C:/private/win-arm64"), "window", "missing", "component_file"),
        (PermissionError("C:/private/data"), "data_directory", "missing", "data_unavailable"),
        (OSError(errno.ENOSPC, "private volume"), "database", "unknown", "disk_full"),
        (desktop.ValidationError("private setting"), "configuration", "missing", "configuration"),
        (RuntimeError("private renderer"), "window", "missing", "webview2_missing"),
        (RuntimeError("private renderer"), "window", "unknown", "window_unverified"),
        (RuntimeError("private renderer"), "window", "available", "startup"),
        (PermissionError("private library"), "window", "available", "startup"),
        (RuntimeError("private server"), "server", "missing", "startup"),
        (KeyboardInterrupt("private interrupt"), "window", "unknown", "window_unverified"),
    ],
)
def test_startup_classification_uses_evidence_without_private_details(
    error, stage, runtime_status, expected
):
    category = desktop._classify_startup_error(error, stage=stage, webview2_status=runtime_status)
    assert category == expected
    message = desktop._STARTUP_MESSAGES[category]
    assert "private" not in message and "C:/" not in message
    assert str(error) not in message


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (sqlite3.SQLITE_CORRUPT, "data_corrupt"),
        (sqlite3.SQLITE_NOTADB, "data_corrupt"),
        (sqlite3.SQLITE_READONLY | (1 << 8), "data_unavailable"),
        (sqlite3.SQLITE_CANTOPEN, "data_unavailable"),
        (sqlite3.SQLITE_BUSY, "data_busy"),
        (sqlite3.SQLITE_LOCKED, "data_busy"),
        (sqlite3.SQLITE_FULL, "disk_full"),
        (sqlite3.SQLITE_ERROR, "database"),
    ],
)
def test_startup_sqlite_classification_uses_result_codes_not_error_text(code, expected):
    error = sqlite3.DatabaseError("private path and arbitrary text")
    error.sqlite_errorcode = code
    assert desktop._classify_startup_error(error, stage="database") == expected


@pytest.mark.parametrize(
    ("result", "has_version", "expected"),
    [
        (0, True, "available"),
        (0, False, "unknown"),
        (0x80070002, False, "missing"),
        (-2147024894, False, "missing"),
        (0x80070005, False, "unknown"),
        (0x80004005, True, "unknown"),
    ],
)
def test_webview2_native_query_only_treats_documented_hresult_as_missing(
    result, has_version, expected
):
    calls, released = [], []

    def query(folder, pointer):
        calls.append(folder)
        if has_version:
            pointer._obj.value = 1234
        return result

    def free_memory(pointer):
        released.append(pointer.value)

    loader = SimpleNamespace(GetAvailableCoreWebView2BrowserVersionString=query)
    assert desktop._probe_webview2_loader(loader, free_memory) == expected
    assert calls == [None]
    assert released == ([1234] if has_version else [])
    assert query.restype == desktop.ctypes.c_int32


def test_webview2_detection_uses_packaged_loader_without_changing_environment(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(desktop.ctypes, "sizeof", lambda value: 8)
    imported, resolved, loaded = [], [], []

    def dll_path(architecture):
        resolved.append(architecture)
        return str(tmp_path / architecture)

    def load_module(name):
        imported.append(name)
        return SimpleNamespace(interop_dll_path=dll_path)

    loader = object()

    def load_native(path):
        loaded.append(path)
        return loader

    free = object()
    monkeypatch.setattr(desktop.importlib, "import_module", load_module)
    monkeypatch.setattr(desktop.ctypes, "WinDLL", load_native, raising=False)
    monkeypatch.setattr(
        desktop.ctypes,
        "windll",
        SimpleNamespace(ole32=SimpleNamespace(CoTaskMemFree=free)),
        raising=False,
    )
    monkeypatch.setattr(
        desktop,
        "_probe_webview2_loader",
        lambda native, release: "available" if native is loader and release is free else "unknown",
    )
    assert desktop._webview2_runtime_status() == "available"
    assert imported == ["webview.util"]
    assert resolved == ["win-x64"]
    assert loaded == [str(tmp_path / "win-x64" / "WebView2Loader.dll")]


def test_missing_packaged_loader_does_not_mean_installed_webview2_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")

    monkeypatch.setattr(
        desktop.importlib,
        "import_module",
        lambda name: SimpleNamespace(interop_dll_path=lambda architecture: str(tmp_path)),
    )

    def missing(_path):
        raise FileNotFoundError("private bundled DLL path")

    monkeypatch.setattr(desktop.ctypes, "WinDLL", missing, raising=False)
    assert desktop._webview2_runtime_status() == "unknown"


def test_corrupt_database_failure_preserves_bytes_and_releases_lock(tmp_path, monkeypatch):
    database = tmp_path / "sentinel.db"
    original = b"private invalid SQLite file that must not be replaced"
    database.write_bytes(original)
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: FakeWebview())

    def show(message, **kwargs):
        assert message == desktop._STARTUP_MESSAGES["data_corrupt"]
        assert "private" not in message and str(tmp_path) not in message
        probe = desktop.InstanceLock(tmp_path)
        probe.acquire()
        probe.release()

    monkeypatch.setattr(desktop, "_show_message", show)
    assert desktop.main(["--data-dir", str(tmp_path)]) == 1
    assert database.read_bytes() == original
    assert "DatabaseError" in (tmp_path / "startup-error.log").read_text(encoding="utf-8")


def test_unusable_data_directory_does_not_probe_webview_or_replace_existing_file(
    tmp_path, monkeypatch
):
    directory = tmp_path / "private-data"
    original = b"private existing file"
    directory.write_bytes(original)
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: FakeWebview())

    def no_probe():
        raise AssertionError("A data directory failure is not evidence about WebView2")

    messages = []
    monkeypatch.setattr(desktop, "_webview2_runtime_status", no_probe)
    monkeypatch.setattr(desktop, "_show_message", lambda message: messages.append(message))
    assert desktop.main(["--data-dir", str(directory)]) == 1
    assert messages == [desktop._STARTUP_MESSAGES["data_unavailable"]]
    assert directory.read_bytes() == original


def test_invalid_rules_fail_before_monitor_start_and_keep_database(tmp_path, monkeypatch):
    store = desktop.EventStore(tmp_path)
    store.close()
    database = tmp_path / "sentinel.db"
    original = database.read_bytes()
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: FakeWebview())

    def invalid_rules():
        raise desktop.ValidationError("private rule configuration")

    def no_monitor(*args, **kwargs):
        raise AssertionError("Invalid rules must fail before a monitor is constructed")

    messages = []
    monkeypatch.setattr(desktop, "load_rules", invalid_rules)
    monkeypatch.setattr(desktop, "LiveMonitor", no_monitor)
    monkeypatch.setattr(desktop, "_show_message", lambda message: messages.append(message))
    assert desktop.main(["--data-dir", str(tmp_path)]) == 1
    assert messages == [desktop._STARTUP_MESSAGES["configuration"]]
    assert database.read_bytes() == original
    lock = desktop.InstanceLock(tmp_path)
    lock.acquire()
    lock.release()


@pytest.mark.parametrize("stage", ["data_directory", "configuration", "window"])
def test_main_failure_cleans_up_before_probe_and_message(tmp_path, monkeypatch, stage):
    runtime = FakeRuntime(tmp_path)
    runtime.startup_stage = stage
    error = (
        PermissionError("private directory")
        if stage == "data_directory"
        else desktop.ValidationError("private rules")
        if stage == "configuration"
        else RuntimeError("private window")
    )
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop, "DesktopRuntime", lambda path: runtime)
    monkeypatch.setattr(desktop.importlib, "import_module", lambda name: FakeWebview())

    def fail(*args):
        raise error

    def probe():
        assert runtime.closed
        return "missing"

    messages = []

    def show(message, **kwargs):
        assert runtime.closed
        assert "private" not in message
        messages.append(message)

    monkeypatch.setattr(desktop, "_run_window", fail)
    monkeypatch.setattr(desktop, "_webview2_runtime_status", probe)
    monkeypatch.setattr(desktop, "_show_message", show)
    assert desktop.main(["--data-dir", str(tmp_path)]) == 1
    expected = {
        "data_directory": "data_unavailable",
        "configuration": "configuration",
        "window": "webview2_missing",
    }[stage]
    assert messages == [desktop._STARTUP_MESSAGES[expected]]


def test_source_run_without_stderr_never_opens_native_dialog(monkeypatch):
    called = []
    monkeypatch.setattr(desktop.platform, "system", lambda: "Windows")
    monkeypatch.setattr(desktop.sys, "frozen", False, raising=False)
    monkeypatch.setattr(desktop.sys, "stderr", None)
    monkeypatch.setattr(
        desktop.ctypes,
        "windll",
        SimpleNamespace(user32=SimpleNamespace(MessageBoxW=lambda *args: called.append(args))),
        raising=False,
    )
    desktop._show_message("Kısa hata")
    assert called == []
