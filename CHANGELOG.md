# Changelog

## 0.4.0 preview — 2026-11-06

- Added first-use guidance and source-health explanations that distinguish unavailable, empty, partial, and healthy collection results.
- Added a Turkish explanation catalog for all 10 bundled rules, with evidence, limitations, and suggested investigation steps.
- Added persistent per-alert review states (`new`, `reviewed`, `expected`) and notes of up to 500 Unicode characters. Review state is separate from the unread count.
- Added schema-1 local preferences for notifications, minimum severity, and the scan interval. Defaults are notifications off, medium severity, and 15 seconds; interval changes persist across restarts.
- Added an additive SQLite 0/1→2 migration for preferences and unread/notification metadata while preserving existing reviews, raw alerts, and evidence.
- Added opt-in Windows native notification attempts with fixed generic text that excludes event details. Queue acceptance does not prove display; Windows may suppress delivery. Historical/replayed alerts do not produce a notification storm.
- Kept notifications tied to the open desktop window; closing it stops monitoring, the local server, and notification resources.
- Automated local validation passed (449 tests, 1 expected Windows symlink skip; 93.61% branch-measured coverage). CI outcomes belong to the candidate's run record. The native GUI, notification delivery, clean-machine startup, and controlled Windows alert scenarios remain unverified by the read-only checkpoint.

## 0.3.0 — 2026-11-05

- Added an optional Windows desktop window using pywebview and the existing WebView2 Runtime, with an automatically chosen loopback port.
- Added a per-user instance lock, persistent Local AppData storage, and monitor/server cleanup when the window closes.
- Added a windowed folder-based PyInstaller build, portable ZIP/checksums/manifests, and third-party notices. Python is bundled for target computers; WebView2 remains a system prerequisite.
- Added a separate manual Windows packaging workflow. Core CLI dependencies remain unchanged, with desktop/build dependencies available as optional extras.
- Preserved existing repository databases without automatic migration; portable artifacts exclude live event history. Hardware integration remains future work.

## 0.2.0 — 2026-11-05

- Added real read-only collection of selected Windows System, Security, and Defender events, with truthful per-channel availability and capped-result reporting.
- Added a Turkish browser dashboard restricted to IPv4 loopback, local event/alert history, evidence inspection, and bounded export.
- Added persistent SQLite storage with retention limits, retained-event deduplication, and restart reconstruction of detection state.
- Added recovery of missing alerts from retained chronological events, evidence snapshots before batch pruning, and rolling-lookback retries for unhealthy sources.
- Added Windows baseline rules and explicit handling of late observations without fabricating alerts.
- Added one-time `collect-windows`, the `serve` command, and a Windows launcher with a project-local Python environment.
- Kept synthetic demo data separate from real monitoring; embedded/RF hardware integrations remain future work.

## 0.1.0 — 2026-11-05

Initial local telemetry and detection release.

- Added strict JSONL collection and normalized, content-addressed events.
- Added TOML detection rules with typed conditions, grouped event-time thresholds, cooldowns, and bounded state.
- Added local event, alert, and summary output, deterministic synthetic demonstration data, and automated tests.
- Added package metadata, architecture and security documentation, and GitHub Actions for tests and installed-package verification.

Hardware adapters for RF Canvas, CSI Radar, and LabMate remain future work.
