"""Optional, window-scoped Windows notifications; importing this loads no .NET.

Only fixed generic text crosses into the Windows shell. Queue acceptance and a
successful ShowBalloonTip call do not prove delivery: Windows may suppress it.
"""

from __future__ import annotations

import contextlib
import importlib
import platform
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any

_TITLE = "Sauron Sentinel"
_REGULAR_TEXT = "Yeni bir güvenlik uyarısı var. Ayrıntıları Sauron Sentinel penceresinde inceleyin."
_TEST_TEXT = "Bu bir deneme bildirimidir; güvenlik alarmı değildir."


@dataclass(frozen=True)
class _WinFormsBindings:
    forms: Any
    action: Any
    system_icons: Any


def _load_winforms() -> _WinFormsBindings:
    # pywebview's selected WinForms backend has already loaded these assemblies.
    # Keep optional pythonnet/.NET imports out of base CLI and Linux imports.
    return _WinFormsBindings(
        importlib.import_module("System.Windows.Forms"),
        importlib.import_module("System").Action,
        importlib.import_module("System.Drawing").SystemIcons,
    )


class WindowsNotificationAdapter:
    """A two-kind coalescing queue drained exclusively by the existing GUI loop.

    pywebview 6.2.1 creates ``window.native`` as its WinForms BrowserForm, with
    an existing handle, and emits its synchronous ``before_show`` on that form's
    STA thread. Native Shown/FormClosed events avoid pywebview's asynchronous
    shown/closed callbacks. This adapter starts no extra thread or message loop.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._supported = platform.system() == "Windows"
        self._available = False
        self._last_error = "not_initialized" if self._supported else "unsupported_platform"
        self._closed = False
        self._bound = False
        self._initialized = False
        self._pending: deque[bool] = deque(maxlen=2)
        self._form = None
        self._bindings: _WinFormsBindings | None = None
        self._icon = None
        self._timer = None
        self._shown_attached = False
        self._closed_attached = False
        self._tick_attached = False
        self._shown_handler = self._on_shown
        self._closed_handler = self._on_form_closed
        self._tick_handler = self._on_tick

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"available": self._available, "last_error": self._last_error}

    def notify(self, *, test: bool = False) -> bool:
        """Accept/coalesce a fixed message without calling or waiting for the UI."""
        with self._lock:
            if not self._available or self._closed:
                return False
            kind = bool(test)
            if kind not in self._pending:
                self._pending.append(kind)
            return True

    def bind(self, window) -> None:
        """Attach to the real pywebview form; unavailable is a graceful fallback."""
        with self._lock:
            if self._closed or self._bound or not self._supported:
                return
            self._bound = True
        try:
            bindings = _load_winforms()
            form = window.native
            with self._lock:
                if self._closed:
                    return
                self._bindings, self._form = bindings, form
            self._dispatch(self._attach_on_ui)
        except Exception:
            self._fail("native_unavailable")

    def _dispatch(self, callback) -> None:
        with self._lock:
            form, bindings = self._form, self._bindings
        if form is None or bindings is None:
            return
        # BeginInvoke(Delegate) is asynchronous and safe from any thread. Never
        # create a handle on a collector/HTTP thread when InvokeRequired is false.
        # https://learn.microsoft.com/dotnet/api/system.windows.forms.control.begininvoke
        # https://learn.microsoft.com/dotnet/api/system.windows.forms.control.invokerequired
        if not form.IsHandleCreated:
            raise RuntimeError("Native notification handle unavailable")
        if form.InvokeRequired:
            form.BeginInvoke(bindings.action(callback))
        else:
            callback()

    def _attach_on_ui(self) -> None:
        with self._lock:
            if self._closed:
                return
            form = self._form
        try:
            form.FormClosed += self._closed_handler
            self._closed_attached = True
            form.Shown += self._shown_handler
            self._shown_attached = True
            if form.Visible:
                self._on_shown()
        except Exception:
            self._fail("native_unavailable")
            self._dispose_on_ui()

    def _on_shown(self, *_args) -> None:
        with self._lock:
            if self._closed or self._initialized:
                return
            self._initialized = True
            bindings = self._bindings
        try:
            self._icon = bindings.forms.NotifyIcon()
            # This framework-owned shared icon is never disposed by us.
            self._icon.Icon = bindings.system_icons.Application
            self._icon.Text = _TITLE
            self._icon.Visible = True
            self._timer = bindings.forms.Timer()
            self._timer.Interval = 1000
            self._timer.Tick += self._tick_handler
            self._tick_attached = True
            # WinForms Timer uses the existing window's UI message pump.
            # https://learn.microsoft.com/dotnet/api/system.windows.forms.timer
            self._timer.Start()
            with self._lock:
                if not self._closed:
                    self._available = True
                    self._last_error = None
                    return
            self._dispose_on_ui()
        except Exception:
            self._fail("native_unavailable")
            self._dispose_on_ui()

    def _on_tick(self, *_args) -> None:
        with self._lock:
            if self._closed or not self._available or not self._pending:
                return
            test = self._pending.popleft()
            icon, bindings = self._icon, self._bindings
        try:
            # Verified .NET Framework overload: (Int32, String, String, ToolTipIcon).
            # Windows controls timing/suppression; this is an attempt, not a receipt.
            # https://learn.microsoft.com/dotnet/api/system.windows.forms.notifyicon.showballoontip
            icon.ShowBalloonTip(
                5000, _TITLE, _TEST_TEXT if test else _REGULAR_TEXT, bindings.forms.ToolTipIcon.Info
            )
        except Exception:
            self._fail("notification_failed")
            self._dispose_on_ui()

    def _fail(self, code: str) -> None:
        with self._lock:
            self._available = False
            self._last_error = code
            self._pending.clear()

    def _mark_closed(self) -> bool:
        with self._lock:
            first_close = not self._closed
            self._closed = True
            self._available = False
            self._pending.clear()
            return first_close

    def close(self) -> None:
        """Stop accepting immediately; never block a worker waiting for the UI."""
        if not self._mark_closed():
            return
        try:
            self._dispatch(self._dispose_on_ui)
        except Exception:
            # Normal FormClosed cleanup runs directly on the UI thread even if
            # a shutdown-time BeginInvoke cannot reach an exiting message pump.
            self._fail("native_unavailable")

    def _on_form_closed(self, *_args) -> None:
        # FormClosed is raised by the native form's UI thread, before its message
        # pump exits. Dispose here even if a worker has already requested close.
        # https://learn.microsoft.com/dotnet/api/system.windows.forms.form.formclosed
        self._mark_closed()
        self._dispose_on_ui()

    def _dispose_on_ui(self) -> None:
        with self._lock:
            form, icon, timer = self._form, self._icon, self._timer
            self._form = self._icon = self._timer = None
            self._available = False
            self._pending.clear()
        # One failing disposal must not skip the other acquired native resources.
        if timer is not None:
            with contextlib.suppress(Exception):
                timer.Stop()
            if self._tick_attached:
                with contextlib.suppress(Exception):
                    timer.Tick -= self._tick_handler
            with contextlib.suppress(Exception):
                timer.Dispose()
        if icon is not None:
            with contextlib.suppress(Exception):
                icon.Visible = False
            with contextlib.suppress(Exception):
                icon.Dispose()
        if form is not None:
            if self._shown_attached:
                with contextlib.suppress(Exception):
                    form.Shown -= self._shown_handler
            if self._closed_attached:
                with contextlib.suppress(Exception):
                    form.FormClosed -= self._closed_handler
        self._tick_attached = self._shown_attached = self._closed_attached = False
