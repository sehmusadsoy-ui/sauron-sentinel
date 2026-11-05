"""Native notification lifecycle using a fake GUI loop, never real balloons."""

from __future__ import annotations

import threading
from collections import deque
from types import SimpleNamespace

import pytest

from sauron_sentinel import native_notifications as native


class EventHook:
    def __init__(self, ui, *, fail_attach=False):
        self.ui = ui
        self.handlers = []
        self.fail_attach = fail_attach

    def __iadd__(self, callback):
        self.ui.assert_ui()
        if self.fail_attach:
            raise RuntimeError("private event failure")
        self.handlers.append(callback)
        return self

    def __isub__(self, callback):
        self.ui.assert_ui()
        self.handlers.remove(callback)
        return self

    def fire(self):
        self.ui.assert_ui()
        for callback in self.handlers[:]:
            callback(None, None)


class FakeUI:
    def __init__(self, *, failure=None):
        self.owner = threading.get_ident()
        self.posted = deque()
        self.icons = []
        self.timers = []
        self.failure = failure
        self.adapter = None
        self.imports = 0
        self.shared_icon = object()

    def assert_ui(self):
        assert threading.get_ident() == self.owner
        if self.adapter is not None:
            # Native calls must never run with the adapter's Python lock held.
            assert self.adapter._lock.acquire(blocking=False)
            self.adapter._lock.release()

    def drain(self):
        self.assert_ui()
        while self.posted:
            self.posted.popleft()()

    def load(self):
        self.imports += 1
        if self.failure == "import":
            raise ImportError("C:/private/component")
        return native._WinFormsBindings(
            SimpleNamespace(
                NotifyIcon=lambda: FakeIcon(self),
                Timer=lambda: FakeTimer(self),
                ToolTipIcon=SimpleNamespace(Info="info"),
            ),
            lambda callback: callback,
            SimpleNamespace(Application=self.shared_icon),
        )


class FakeForm:
    def __init__(self, ui, *, has_handle=True):
        self.ui = ui
        self.IsHandleCreated = has_handle
        self._visible = False
        self.Shown = EventHook(ui, fail_attach=ui.failure == "attach")
        self.FormClosed = EventHook(ui)

    @property
    def InvokeRequired(self):
        return threading.get_ident() != self.ui.owner

    @property
    def Visible(self):
        self.ui.assert_ui()
        return self._visible

    def BeginInvoke(self, callback):
        self.ui.posted.append(callback)

    def show(self):
        self._visible = True
        self.Shown.fire()

    def close(self):
        self._visible = False
        self.FormClosed.fire()
        self.IsHandleCreated = False


class FakeIcon:
    def __init__(self, ui):
        ui.assert_ui()
        if ui.failure == "icon_ctor":
            raise RuntimeError("private icon failure")
        self.ui = ui
        self.calls = []
        self.disposals = 0
        self._visible = False
        ui.icons.append(self)

    @property
    def Icon(self):
        return self._icon

    @Icon.setter
    def Icon(self, value):
        self.ui.assert_ui()
        self._icon = value

    @property
    def Text(self):
        return self._text

    @Text.setter
    def Text(self, value):
        self.ui.assert_ui()
        self._text = value

    @property
    def Visible(self):
        return self._visible

    @Visible.setter
    def Visible(self, value):
        self.ui.assert_ui()
        if value and self.ui.failure == "icon_visible":
            raise RuntimeError("private shell failure")
        self._visible = value

    def ShowBalloonTip(self, *args):
        self.ui.assert_ui()
        if self.ui.failure == "balloon":
            raise RuntimeError("C:/private/user context")
        self.calls.append(args)

    def Dispose(self):
        self.ui.assert_ui()
        self.disposals += 1


class FakeTimer:
    def __init__(self, ui):
        ui.assert_ui()
        if ui.failure == "timer_ctor":
            raise RuntimeError("private timer failure")
        self.ui = ui
        self.Tick = EventHook(ui)
        self.running = False
        self.disposals = 0
        ui.timers.append(self)

    @property
    def Interval(self):
        return self._interval

    @Interval.setter
    def Interval(self, value):
        self.ui.assert_ui()
        self._interval = value

    def Start(self):
        self.ui.assert_ui()
        if self.ui.failure == "timer_start":
            raise RuntimeError("private timer start failure")
        self.running = True

    def Stop(self):
        self.ui.assert_ui()
        if self.ui.failure == "timer_stop":
            raise RuntimeError("private timer stop failure")
        self.running = False

    def Dispose(self):
        self.ui.assert_ui()
        self.running = False
        self.disposals += 1


def make_adapter(monkeypatch, *, failure=None, has_handle=True):
    ui = FakeUI(failure=failure)
    monkeypatch.setattr(native.platform, "system", lambda: "Windows")
    monkeypatch.setattr(native, "_load_winforms", ui.load)
    adapter = ui.adapter = native.WindowsNotificationAdapter()
    form = FakeForm(ui, has_handle=has_handle)
    return adapter, ui, form, SimpleNamespace(native=form)


def on_worker(callback):
    errors = []

    def run():
        try:
            callback()
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(timeout=2)
    assert not worker.is_alive(), "Notification operation blocked a worker"
    if errors:
        raise errors[0]


def ready_adapter(monkeypatch, **kwargs):
    adapter, ui, form, window = make_adapter(monkeypatch, **kwargs)
    adapter.bind(window)
    form.show()
    return adapter, ui, form, window


def assert_disposed(ui, form):
    assert all(icon.disposals == 1 and not icon.Visible for icon in ui.icons)
    assert all(timer.disposals == 1 and not timer.running for timer in ui.timers)
    assert all(not timer.Tick.handlers for timer in ui.timers)
    assert not form.Shown.handlers and not form.FormClosed.handlers


def test_construction_snapshot_and_unbound_close_load_no_native_dependencies(monkeypatch):
    adapter, ui, _form, _window = make_adapter(monkeypatch)
    assert adapter.snapshot() == {"available": False, "last_error": "not_initialized"}
    assert adapter.notify() is False and adapter.notify(test=True) is False
    adapter.close()
    adapter.close()
    assert ui.imports == 0 and not ui.icons and not ui.timers and not ui.posted


def test_non_windows_bind_is_unavailable_without_import(monkeypatch):
    adapter, ui, _form, window = make_adapter(monkeypatch)
    monkeypatch.setattr(native.platform, "system", lambda: "Linux")
    adapter = native.WindowsNotificationAdapter()
    adapter.bind(window)
    assert adapter.snapshot() == {"available": False, "last_error": "unsupported_platform"}
    assert adapter.notify(test=True) is False
    adapter.close()
    assert ui.imports == 0


def test_bind_waits_for_actual_native_shown_and_never_sends_automatically(monkeypatch):
    adapter, ui, form, window = make_adapter(monkeypatch)
    adapter.bind(window)
    adapter.bind(window)
    assert ui.imports == 1 and not ui.icons and not ui.timers
    assert adapter.snapshot()["available"] is False
    form.show()
    form.Shown.fire()
    assert adapter.snapshot() == {"available": True, "last_error": None}
    assert len(ui.icons) == len(ui.timers) == 1
    assert ui.icons[0].Visible and ui.icons[0].Icon is ui.shared_icon
    assert ui.timers[0].running and ui.timers[0].Interval == 1000
    ui.timers[0].Tick.fire()
    assert not ui.icons[0].calls
    form.close()
    assert_disposed(ui, form)


def test_bind_from_worker_marshals_creation_to_existing_ui_loop(monkeypatch):
    adapter, ui, form, window = make_adapter(monkeypatch)
    form.show()
    on_worker(lambda: adapter.bind(window))
    assert not ui.icons and not form.FormClosed.handlers
    assert adapter.snapshot()["available"] is False
    assert len(ui.posted) == 1
    ui.drain()
    assert adapter.snapshot()["available"] is True
    form.close()
    assert_disposed(ui, form)


def test_worker_queue_coalesces_and_sends_only_two_fixed_messages_on_ui(monkeypatch):
    adapter, ui, form, _window = ready_adapter(monkeypatch)

    def burst():
        for _ in range(1000):
            assert adapter.notify() is True
            assert adapter.notify(test=True) is True

    on_worker(burst)
    assert list(adapter._pending) == [False, True]
    assert not ui.posted and not ui.icons[0].calls
    ui.timers[0].Tick.fire()
    assert len(ui.icons[0].calls) == 1
    ui.timers[0].Tick.fire()
    ui.timers[0].Tick.fire()
    assert ui.icons[0].calls == [
        (5000, "Sauron Sentinel", native._REGULAR_TEXT, "info"),
        (5000, "Sauron Sentinel", native._TEST_TEXT, "info"),
    ]
    assert "deneme" in native._TEST_TEXT and "güvenlik alarmı değildir" in native._TEST_TEXT
    form.close()
    assert_disposed(ui, form)


def test_worker_close_is_nonblocking_idempotent_and_disposes_on_ui(monkeypatch):
    adapter, ui, form, _window = ready_adapter(monkeypatch)
    adapter.notify()
    on_worker(lambda: (adapter.close(), adapter.close()))
    assert adapter.snapshot()["available"] is False
    assert adapter.notify(test=True) is False
    assert len(ui.posted) == 1 and not adapter._pending
    assert ui.icons[0].disposals == 0
    ui.timers[0].Tick.fire()
    assert not ui.icons[0].calls
    ui.drain()
    assert_disposed(ui, form)
    adapter.close()
    assert not ui.posted


def test_native_close_disposes_before_ui_loop_exits_even_with_pending_worker_close(monkeypatch):
    adapter, ui, form, _window = ready_adapter(monkeypatch)
    on_worker(adapter.close)
    assert ui.posted
    form.close()
    assert_disposed(ui, form)
    ui.drain()
    adapter.close()
    assert_disposed(ui, form)


def test_close_before_posted_bind_prevents_initialization(monkeypatch):
    adapter, ui, form, window = make_adapter(monkeypatch)
    on_worker(lambda: (adapter.bind(window), adapter.close()))
    ui.drain()
    form.show()
    assert not ui.icons and not ui.timers
    assert adapter.snapshot()["available"] is False
    assert not form.Shown.handlers and not form.FormClosed.handlers


@pytest.mark.parametrize("failure", ["import", "attach"])
def test_binding_failures_are_generic_and_leave_no_handlers(monkeypatch, failure):
    adapter, ui, form, window = make_adapter(monkeypatch, failure=failure)
    adapter.bind(window)
    assert adapter.snapshot() == {"available": False, "last_error": "native_unavailable"}
    assert not ui.icons and not ui.timers
    adapter.close()
    assert not form.Shown.handlers and not form.FormClosed.handlers


@pytest.mark.parametrize("failure", ["icon_ctor", "icon_visible", "timer_ctor", "timer_start"])
def test_partial_native_initialization_always_cleans_acquired_resources(monkeypatch, failure):
    adapter, ui, form, _window = ready_adapter(monkeypatch, failure=failure)
    assert adapter.snapshot() == {"available": False, "last_error": "native_unavailable"}
    assert adapter.notify(test=True) is False
    assert_disposed(ui, form)
    adapter.close()
    assert_disposed(ui, form)


def test_balloon_error_disables_adapter_without_exposing_private_details(monkeypatch):
    adapter, ui, form, _window = ready_adapter(monkeypatch, failure="balloon")
    assert adapter.notify(test=True) is True
    ui.timers[0].Tick.fire()
    assert adapter.snapshot() == {"available": False, "last_error": "notification_failed"}
    assert adapter.notify() is False
    assert_disposed(ui, form)
    adapter.close()


def test_cleanup_continues_when_a_native_stop_operation_fails(monkeypatch):
    adapter, ui, form, _window = ready_adapter(monkeypatch, failure="timer_stop")
    form.close()
    assert_disposed(ui, form)
    assert adapter.snapshot()["available"] is False


def test_missing_handle_is_never_created_on_a_worker(monkeypatch):
    adapter, ui, form, window = make_adapter(monkeypatch, has_handle=False)
    on_worker(lambda: adapter.bind(window))
    assert adapter.snapshot() == {"available": False, "last_error": "native_unavailable"}
    assert not ui.posted and not ui.icons and not ui.timers
    assert not form.IsHandleCreated
    adapter.close()
