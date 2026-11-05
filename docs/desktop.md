# Windows desktop edition

Version 0.3.0 adds an optional native window around Sentinel's local dashboard. It shares the Windows collector, normalization, rule engine, and SQLite model with CLI monitoring. No RF/embedded hardware adapter is added by the desktop wrapper.

## Run the portable ZIP

1. Download `Sauron-Sentinel-0.3.0-Windows-x64.zip` from the repository's [releases](https://github.com/sehmusadsoy-ui/sauron-sentinel/releases).
2. Extract the complete archive into a writable location.
3. Open `SauronSentinel` and double-click `SauronSentinel.exe`.
4. Close the window when finished. Its monitor and local HTTP server stop with the application.

The portable folder includes the executable and its support files. Keep them together. The target computer does not need Python, pip, a virtual environment, or the source repository. This is a folder-based portable build, not a single self-contained executable or an installer.

No autostart entry, service, desktop shortcut, or administrator prompt is created. Windows permissions still determine which event channels can be read. An inaccessible Security log remains visibly unavailable.

## Requirements

- Windows 10/11 x64.
- An existing Microsoft Edge WebView2 Runtime and the Windows .NET facilities needed by the desktop host.
- A writable per-user Local AppData directory.

Sentinel explicitly uses the EdgeChromium renderer and does not download or install WebView2 automatically. If the runtime is missing, obtain it from [Microsoft's WebView2 page](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) through your normal software-management process. A normal Edge browser installation is not a substitute for the WebView2 Runtime requirement. Microsoft's [distribution documentation](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution) explains that distinction.

The distributed executable is unsigned. Windows may identify its publisher as unknown. The release checksum allows comparison with the published archive; it is not a signing certificate or an independent trust guarantee.

## Local data and upgrades

Desktop state belongs to the current user under:

```text
%LOCALAPPDATA%\SauronSentinel
```

The database is separate from the portable application files. Replacing or moving the extracted application folder does not intentionally copy your telemetry into the package. The build starts from application resources and does not include live databases, captures, or personal run directories.

Existing browser/source-mode data under a repository's `sentinel-data` is not migrated or imported automatically. Desktop mode begins with its own per-user store. Preserve any older source-mode history separately when needed.

Only one desktop instance may use this data location at a time. Close the existing window before launching another copy. Do not run multiple builds against the same database deliberately.

The `sentinel.db` file holds monitoring history. `desktop.lock` may remain after the app closes; the operating system releases its lock, so the file's presence alone does not mean Sentinel is still running. The `webview` subdirectory belongs to the desktop renderer.

If startup fails, `startup-error.log` records the last exception locally after monitoring is stopped. It can contain local filesystem paths; review or redact it before sharing. Logs are excluded from portable packages and are never uploaded automatically.

Close Sentinel before backing up, moving, or removing its data directory. The store contains sensitive plaintext event context and evidence; deleting the application folder alone does not remove this per-user history. Normal retention remains 20,000 events and 2,000 alerts.

## Local server and shutdown

The window displays bundled assets from an HTTP server bound to `127.0.0.1` on an automatically selected available port. It does not require a fixed port or open a LAN/public listener. Browser request checks remain active. The desktop wrapper does not expose a JavaScript API for arbitrary Python execution.

The export button opens a native Save As dialog for the exact local `/api/export` endpoint. Other download URLs and external document navigation are blocked; export files remain local until the operator chooses to share them.

Closing the window initiates monitor shutdown, waits for in-flight collection to finish, closes the server and database, and releases the single-instance lock. A bounded Windows collection can take time to finish; avoid forcibly terminating the process while it is writing data.

There is no background-monitoring service after a normal window close. Existing alerts and retained observations remain available on the next launch, using the same replay/recovery semantics described in the [architecture](architecture.md).

## Source launch

The CLI/core package has no mandatory GUI dependency. On Windows, install the desktop extra only when you want the native window:

```sh
python -m pip install ".[desktop]"
sauron-sentinel-desktop
```

The GUI entry point uses the same per-user data location as the portable build. The earlier `serve` command and source `.cmd` launcher remain browser-based alternatives, using their explicit/default `sentinel-data` location.

## Build the Windows package

Use a Windows x64 build environment with Python 3.14 and a clean virtual environment:

```sh
python -m pip install -e ".[desktop,desktop-build]"
python scripts/build_desktop.py
```

The fixed PyInstaller specification is `packaging/SauronSentinel.spec`. The build produces a windowed folder-based application, a portable ZIP, checksum information, and a build manifest under the workspace's `outputs` directory. It includes license and third-party notices, without live monitoring history.

The verified build uses pywebview 6.2.1, pythonnet 3.2.1, PyInstaller 6.22.3, and pyinstaller-hooks-contrib 2026.9. These top-level optional dependencies are pinned in `pyproject.toml`; dependency imports were checked with Python 3.14.8. A native window check and the frozen-package self-check remain separate validation steps.

The manually triggered **Windows portable** GitHub Actions workflow builds the same artifact on a Windows runner and uploads only the portable package and its manifests. It does not launch the Windows collector against the maintainer's computer or publish a release automatically. A real desktop launch/close check is separate from a successful build.

PyInstaller bundles Python and application dependencies, while WebView2 remains an existing system runtime. The [pywebview freezing guide](https://pywebview.flowrl.com/guide/freezing.html) describes its PyInstaller integration. Neither byte-for-byte reproducible builds nor code signing is claimed.
