# -*- mode: python ; coding: utf-8 -*-
"""Windows x64, single-executable build with explicit application resources."""

from pathlib import Path

from PyInstaller.utils.hooks import copy_metadata

repository = Path(SPECPATH).resolve().parent
package = repository / "src" / "sauron_sentinel"
resources = [
    "defaults.toml",
    "demo.jsonl",
    "windows_collector.ps1",
    "static/index.html",
    "static/app.js",
    "static/styles.css",
]
datas = [
    (str(package / name), str(Path("sauron_sentinel") / Path(name).parent))
    for name in resources
]
# pywebview resolves its own version through distribution metadata. Its official
# PyInstaller hook also collects webview/lib, including managed WebView2 DLLs.
datas += copy_metadata("pywebview")

analysis = Analysis(
    [str(repository / "scripts" / "desktop_entry.py")],
    pathex=[str(repository / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "webview.platforms.winforms",
        "webview.platforms.edgechromium",
        "clr_loader",
        "pythonnet",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PyQt5", "PyQt6", "PySide2", "PySide6", "qtpy", "gi", "gtk",
        "cefpython3", "webview.platforms.cef", "webview.platforms.qt", "webview.platforms.mshtml",
        "webview.platforms.gtk", "webview.platforms.cocoa", "webview.platforms.android",
        "tkinter", "pytest", "_pytest", "coverage", "ruff", "numpy", "matplotlib",
    ],
    noarchive=False,
    optimize=1,
)
# Retain upstream managed/native resources: pywebview checks the ARM64, x64 and
# x86 runtime directories during import even when only the x64 loader is used.
archive = PYZ(analysis.pure)
executable = EXE(
    archive,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    name="SauronSentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    icon=str(repository / "packaging" / "sentinel.ico"),
    version=str(repository / "packaging" / "version_info.txt"),
    uac_admin=False,
    uac_uiaccess=False,
)
