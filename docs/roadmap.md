# Roadmap

This document separates shipped behavior from proposals. Milestones are acceptance criteria, not compatibility claims or delivery commitments.

## 0.1 — Local telemetry foundation

- Streaming JSONL ingestion, strict versioned normalization, and deterministic event references.
- Declarative event-time detection with bounded state and cooldowns.
- Synthetic fixtures, tests, batch evidence output, and package/CI checks.

## 0.2 — Local Windows monitoring

- Read-only, selected-event Windows collector with per-channel availability and bounded results.
- Turkish loopback browser dashboard with a real event timeline and explainable alert evidence.
- SQLite history, bounded retention, recollection deduplication, and restart/recovery replay that saves previously missing alerts.
- Windows launcher with project-local setup and no automatic elevation or policy changes.
- Permission, empty-source, cap, and late-event reporting; zero alerts remain an honest result.

## 0.3 — Portable Windows desktop

- Optional native application window using the existing local dashboard and WebView2 Runtime.
- Portable Windows x64 folder/ZIP with Python dependencies included, plus checksums and license notices.
- Per-user data outside the package, a single-instance boundary, and clean window-close shutdown.
- Manual Windows package-build workflow; unsigned early release with no installer, autostart, or automatic runtime installation.

## 0.4 preview — Usability and local review

- First-use guidance and source-health explanations, including unavailable, empty, partial, and healthy collection results.
- A Turkish explanation catalog covering all 10 bundled rules, their evidence, limitations, and investigation steps.
- Persistent per-alert `new`, `reviewed`, and `expected` review states, plus notes of up to 500 Unicode characters. The unread count remains separate.
- Schema-1 preferences with notifications off, minimum severity medium, and a 15-second scan interval by default; interval changes persist across restarts.
- Additive SQLite 0/1→2 migration for preferences and unread/notification metadata that preserves existing reviews, raw alerts, and evidence.
- Opt-in, window-scoped Windows native notification attempts using fixed generic text without event details. Queue acceptance does not prove Windows delivery, and historical/replayed alerts do not create a notification storm.
- Closing the desktop window stops monitoring, the local server, and notification resources.

Automated local validation passed (449 tests, 1 expected Windows symlink skip; 93.61% branch-measured coverage). CI outcomes belong to the candidate's run record. Native GUI behavior, notification delivery, clean-machine startup, and controlled Windows alert scenarios remain unverified by the read-only checkpoint. The frozen headless diagnostic checks bundled resources, native library imports, storage, the loopback server, and shutdown; it does not validate the real application window or notification display.

## Next — Hardware contracts and controlled captures

RF Canvas, CSI Radar, and LabMate remain proposed targets involving Flipper Zero and ESP32 where applicable. None has a completed integration in this repository.

A hardware adapter is ready only when it has:

1. A documented export/transport protocol and supported firmware versions.
2. Bounded framing, reconnect/error handling, and explicit device identity.
3. Clock synchronization and a declared late-event policy.
4. Attribute units, calibration metadata, producer version, and provenance rules.
5. Controlled real captures clearly separated from synthetic fixtures.
6. Capture regression tests and an end-to-end hardware validation procedure.

Keep passive acquisition separate from analysis. Any future operation that transmits, changes device configuration, or interacts with a network requires a deliberate interface and authorization model.

## Further investigation work

- Broader, individually documented Windows event coverage and optional OS exporters.
- Controlled labeled scenarios and false-positive analysis with disclosed inputs and evaluation conditions.
- Explicit durable collector cursors/late-arrival handling beyond bounded overlapping queries.
- Configurable retention/export policies and stronger evidence custody when required.
- Cross-source correlation after clock, identity, and provenance contracts are validated.

## Research

Threat-intelligence enrichment, Sigma interoperability, learned anomaly detection, active response, and remote deployment are not implemented. Each requires clear boundaries, repeatable validation, and a maintenance plan before becoming a product capability.
