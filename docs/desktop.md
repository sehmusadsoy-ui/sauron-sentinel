# Windows desktop edition

Version 0.4.0 is an early usability preview adding first-use health guidance, rule explanations, per-alert reviews, persistent preferences, and opt-in Windows notification attempts. It shares the Windows collector, normalization, rule engine, and SQLite model with CLI monitoring. RF Canvas, CSI Radar, and LabMate remain planned only. See the [validation record](validation-v0.4.md) for actual read-only Windows evidence and the native/manual and clean-machine checks not established by that checkpoint.

## Run the portable ZIP

1. Obtain the complete `Sauron-Sentinel-0.4.0-Windows-x64.zip` preview archive when available. Published assets and their actual verification status appear under [releases](https://github.com/sehmusadsoy-ui/sauron-sentinel/releases).
2. Extract the complete archive into a writable location.
3. Open `SauronSentinel` and double-click `SauronSentinel.exe`.
4. Close the window when finished. Its monitor and local HTTP server stop with the application.

The portable folder includes the executable and its support files. Keep them together. The target computer does not need Python, pip, a virtual environment, or the source repository. This is a folder-based portable build, not a single self-contained executable or an installer.

No autostart entry, service, desktop shortcut, or administrator prompt is created. Windows permissions still determine which event channels can be read. An inaccessible Security log remains visibly unavailable.

## First use and alert review

Read the health panel and source cards before interpreting alerts. A successful empty source means the query found no selected records; it does not establish that auditing is configured. Missing, unavailable, capped, failed, and stale results remain distinct. Source last-success times describe this session only. Even when every source is readable, Sentinel does not certify the computer as secure.

Open an alert to see evidence, the rule's matching conditions, possible normal causes, and safe checks. All ten bundled heuristics have explanations; RF/motion examples do not imply a live sensor. Set that alert to `new`, `reviewed`, or `expected` and optionally save a note of up to 500 Unicode characters. This persists locally and does not suppress future matches. Review and unread state are independent: a separate read request follows successful evidence display; saving a review does not mark it read. A read/save error is displayed with a retry path.

## Preferences and Windows notifications

Preferences start with notifications **off**, minimum severity **medium**, and a **15-second** scan interval. Save settings explicitly. The interval menu offers 15, 30, 60, and 300 seconds, and retains a valid saved custom value from the supported 5–3,600-second range. Preferences survive normal closing and reopening. Invalid stored preferences reset to defaults with a visible reset notice.

After opt-in, later eligible alerts can request a generic native notification while this window is open. No account, service, threat, device, evidence, or note content appears in its fixed text. Initial history and the first batch (including a partial batch), historical arrivals, and restart/recovery replay remain read and do not notify. Newly arriving eligible live alerts become unread even if notifications are off. Enabling notifications does not send a backlog.

The **test notification** is explicitly a test, creates no alarm, and requires notifications to be enabled and available. The status distinguishes unavailable, attempted, queued, and failed. **Queued does not mean delivered:** Windows may suppress display. A durable claim prevents a regular alert's attempt being repeated after restart; failures are not retried. Browser/CLI mode retains in-app unread/review functions but reports native notifications unavailable.

The notification icon exists only for the open window. It does not keep Sentinel running in the tray after closure. Native display, suppression, and lifecycle require separate observed manual verification; automated tests do not establish their outcome.

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

The `sentinel.db` file holds monitoring history, review notes, preferences, unread flags, and notification-attempt metadata. Supported SQLite schema 0/1 stores upgrade transactionally to schema 2 without rewriting alert payloads or evidence; existing alerts start read. Keep a private backup before upgrading history you need. `desktop.lock` may remain after the app closes; the operating system releases its lock, so the file's presence alone does not mean Sentinel is still running. The `webview` subdirectory belongs to the desktop renderer.

If startup fails, `startup-error.log` records the last exception locally after monitoring is stopped. It can contain local filesystem paths; review or redact it before sharing. Logs are excluded from portable packages and are never uploaded automatically.

Close Sentinel before backing up, moving, or removing its data directory. The store contains sensitive plaintext event context and evidence; deleting the application folder alone does not remove this per-user history. Normal retention remains 20,000 events and 2,000 alerts.

## Local server and shutdown

The window displays bundled assets from an HTTP server bound to `127.0.0.1` on an automatically selected available port. It does not require a fixed port or open a LAN/public listener. Browser request checks remain active. The desktop wrapper does not expose a JavaScript API for arbitrary Python execution.

The export button opens a native Save As dialog for the exact local `/api/export` endpoint. Other download URLs and external document navigation are blocked; export files remain local until the operator chooses to share them. Live exports include additive review/unread metadata and local state; review notes may contain private information. Raw alert/evidence records remain unchanged.

Closing the window initiates monitor/notification shutdown, waits for in-flight collection to finish, disposes the notification icon/timer, closes the server and database, and releases the single-instance lock. A bounded Windows collection can take time to finish; avoid forcibly terminating the process while it is writing data.

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

The fixed PyInstaller specification is `packaging/SauronSentinel.spec`. The build produces a windowed folder-based application, a portable ZIP, checksum information, and a build manifest under the workspace's `outputs` directory, with versioned working files under `work/desktop-build-0.4.0`. It includes Turkish first-use notes, licenses, and third-party notices, without live monitoring history. Keep the bundled vendor native assemblies for win-arm64, win-x64, and win-x86 intact; the host loads its required assemblies from this layout.

The build configuration pins pywebview 6.2.1, pythonnet 3.2.1, PyInstaller 6.22.3, and pyinstaller-hooks-contrib 2026.9 in `pyproject.toml`; dependency imports were checked with Python 3.14.8 during earlier desktop validation. Each candidate still needs its own frozen-package self-check, content/privacy audit, and recorded checksum. A native window check and clean-machine installation are separate from that self-check.

The manually triggered **Windows portable** GitHub Actions workflow builds the same artifact on a Windows runner and uploads only the portable package and its manifests. It does not launch the Windows collector against the maintainer's computer or publish a release automatically. A real desktop launch/close check is separate from a successful build.

PyInstaller bundles Python and application dependencies, while WebView2 remains an existing system runtime. The [pywebview freezing guide](https://pywebview.flowrl.com/guide/freezing.html) describes its PyInstaller integration. Neither byte-for-byte reproducible builds nor code signing is claimed.
