"""Native hosting lifecycle and safety, without requiring an actual GUI."""

from __future__ import annotations

import json
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


class FakeRuntime:
    def __init__(self, directory):
        self.data_dir = Path(directory)
        self.closed = False
        self.started = False

    def start(self):
        self.started = True
        return "http://127.0.0.1:12345"

    def close(self):
        self.closed = True


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
    runtime = desktop.DesktopRuntime(tmp_path, collector=_empty_collector)
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

    class Store:
        def __init__(self, path):
            if failure_at == "store":
                raise OSError("private failure")

        def close(self):
            closed.append("store")

    class Monitor:
        def __init__(self, store, **kwargs):
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
    runtime = desktop.DesktopRuntime(tmp_path)
    with pytest.raises(OSError):
        runtime.start()
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
