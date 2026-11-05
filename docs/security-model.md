# Security model

## Intended environment

The application runs on one trusted local workstation. It reads selected local Windows event logs with current-user permissions or analyzes JSONL the operator is authorized to process. It is not a hardened multi-user service, endpoint-protection product, or evidence custody system.

## Trust boundaries

Windows records, JSONL input, and TOML configuration are treated as data. The collector validates event channel/provider combinations and selects a small allowlist of useful fields rather than storing full rendered Windows messages or raw XML. Account/service names and threat labels may still be sensitive.

| Risk | Implemented control | Remaining limitation |
| --- | --- | --- |
| Ambiguous input | Strict schema, flat scalars, bounded strings, duplicate-key/non-finite rejection | Valid but misleading data can influence a heuristic |
| Excess resource use | Bounded collector results, subprocess timeout, input sizes, rule state, and stored row counts | Use process/disk controls for adversarial workloads; bounded counts do not promise a fixed byte size |
| Executable rule content | Fixed comparison operators; no `eval`, shell actions, or plugins | Future integrations must preserve the boundary |
| Accidental privilege changes | No elevation, audit-policy edits, or security-setting changes | Some logs will remain unavailable to the current account |
| Dashboard network exposure | Server fixed to `127.0.0.1`; no LAN/public-bind option | Loopback does not defend against hostile local software/users |
| Cross-site browser requests | Host/Origin checks and a session token; locally bundled assets | No user-account authentication or multi-user isolation |
| Overwritten batch evidence | New output directory required | Operators can still alter files afterward |
| Synthetic/live mixing | Separate grouping; live SQLite storage rejects synthetic records | A producer's provenance flag is not a signature |
| Duplicate collection | Content IDs and SQLite uniqueness for retained records | No unlimited deduplication guarantee beyond retention |
| Time ambiguity | Explicit UTC normalization; late observations surfaced separately | Device/system clock correctness is not verified |
| Local review content | Per-alert status allowlist, 500-Unicode-code-point notes, strict JSON/8,192-byte body limit, text rendering | Notes are private plaintext metadata, not a signed audit trail |
| Notification disclosure/repeats | Opt-in default, fixed generic shell text, durable per-alert attempt claim | Windows may suppress display; failed/interrupted attempts are not retried |

## Local data and retention

Browser/CLI mode defaults to `sentinel-data/sentinel.db`. Desktop mode uses a separate per-user directory under `%LOCALAPPDATA%\SauronSentinel` and does not automatically import a repository's existing database. Events, alerts, evidence snapshots, review notes, preferences, unread/attempt metadata, and exports are plaintext. There is no application-managed encryption, tamper seal, or evidentiary signing. Rely on suitable local file permissions and disk protection. Do not commit the database, run directories, or real captures to Git; `.gitignore` includes default data locations but cannot know every custom output path.

Supported SQLite schema 0/1 stores upgrade transactionally to schema 2 with additive local metadata; existing alert/evidence payloads are preserved. Keep a private backup before upgrading needed history. Preferences use strict schema 1, defaulting to notifications off, medium severity, and a 15-second interval. Invalid saved preferences reset to these defaults and report `reset_invalid`. Review state is per alert, not a suppression rule; unread state changes only through the explicit read action, independently of review. Review validation rejects Unicode control/format/surrogate characters except newline/tab. Local exports add review/unread metadata and state without rewriting raw alert/evidence records; notes need the same sharing review as event context.

The portable ZIP contains application code/resources and dependencies, not live event history. Its executable is unsigned; published checksums support download comparison but are not publisher signatures. The package does not install services, autostart entries, or shortcuts and does not elevate privileges. Existing WebView2 is required and is not automatically downloaded or installed. Closing the desktop window stops its monitor, notifications, and server; retained data remains in Local AppData. The notification icon is scoped to the window, not a resident tray service.

The Windows collector includes selected identity/context fields, capped to 256 characters, with truncation marked. It does not store full raw XML/messages. A hashed device label provides a stable local pseudonym, not a strong anonymity guarantee. Arbitrary batch JSONL may contain any allowed attribute strings, so minimize data at the producer and review exports before sharing.

Default retention is 20,000 events and 2,000 alerts. Old rows are pruned and exports are bounded. This is monitoring history, not a complete Windows audit archive. Stop the application before relocating or deleting the data directory.

## Permissions and collection honesty

Sentinel does not request administrator access, create authentication failures, disable protection, or install test services. An accessible source with zero selected events is different from an inaccessible source. Both remain visible in source status. Missing audit policy is not silently repaired.

Health summarizes source access and current-session results, not computer security. Missing sources remain pending, result caps warn of omissions, and failed/stopped monitoring marks old results non-current. A last-success time is session-scoped, not a persisted assurance; the dashboard reports connection loss separately. Readable empty sources cannot establish audit-policy coverage. Search/filter controls inspect only the most recent 100 loaded records.

The launcher can download Python build tools during initial installation. Routine monitoring makes no outbound telemetry upload or threat-intelligence request. Both the launcher and collector respect existing permissions without altering Windows audit or PowerShell execution policy.

## Detection limits

Alerts record rule matches, not verified incidents. A newly installed service, new account, group change, or unexpected shutdown can be legitimate. Defender observations represent the log's reported event; Sentinel is not an antivirus engine. RF and motion sample rules have no implemented hardware source and cannot establish attack intent.

Late events older than the current detection watermark are immediately retained but skipped for that live alert pass. Restart/recovery replay can later add historical alerts from retained records, including missing alerts after a stop between event and alert persistence. Existing alert IDs are not overwritten. Alert evidence is snapshotted before the current batch is pruned; events outside retained history cannot be recovered by replay.

An unhealthy channel causes retries over the configured rolling lookback, while healthy polls use a 120-second overlap. Per-channel caps and limit flags still apply to every retry. Collector result caps, overlap limits, permissions, audit configuration, and retention can all limit coverage. No empirical detection accuracy or false-positive rate is claimed. Database errors do not trigger an automatic reset of existing local data.

## Notification boundary

Notifications default off. Only later eligible live alerts can request one after opt-in, severity filtering, and native availability. The initial batch, historical arrivals, and restart/recovery replay do not create notification/unread storms. Unread state remains available independently of notification settings. Generic fixed regular/test text is the only payload passed to Windows Forms `NotifyIcon`; it contains no event details, identities, paths, or review notes. The test control is explicitly not an alarm and requires opt-in.

A durable claim is committed before a regular notification attempt and prevents a second attempt for the same retained alert after restart. A crash, adapter failure, or later metadata error can therefore lose a notification rather than retry it. `queued` is application queue acceptance, not evidence of Windows display or delivery; the OS may suppress it. Browser mode has no native adapter, and closing the desktop window ends notification resources along with monitoring. There is no cloud push service or background tray monitoring.

The [read-only validation checkpoint](validation-v0.4.md) establishes partial source access and local replay/deduplication only. It does not establish controlled Windows detection accuracy, clean-machine installation, or native GUI/Save As/notification display and lifecycle. Those limits must remain visible in preview/release records.

## Supply chain

The core runtime uses the Python standard library. Optional desktop support adds pywebview and Windows interoperability dependencies and uses Microsoft's installed WebView2 Runtime. Desktop packaging bundles the Python/application dependencies with PyInstaller. Top-level GUI/build/development dependencies are pinned in `pyproject.toml`; transitive dependencies are not locked. Actions use full commit pins, read-only repository permissions, and no retained checkout credentials. CI needs no user-provided secrets and does not publish to a package registry or release automatically.

See [SECURITY.md](../SECURITY.md) for responsible reporting.
