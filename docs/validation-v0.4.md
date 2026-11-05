# v0.4 validation record

Validated on 2026-11-06 (Europe/Istanbul), against source commit
`267bcee5e85d215ada31ce5f7c9feff6eb3ae54e` on `codex/v0.4-usability`.
This is a development checkpoint; the source still reported version 0.3.0.

The adjusted Phase 4 read-only check completed on the current Windows PC.
Collection correctly reported **partial** access. This does not complete a
controlled Windows laboratory, native-window, or release-readiness gate. The
operator has no separate VM or spare PC; none was used or assumed.

## Automated evidence

The independently reviewed Phase 3 baseline is **448 passed, 1 skipped, 93.61%
coverage with branch measurement**. The skip is the known Windows
directory-symlink permission case. That baseline also passed Ruff lint/format,
JavaScript syntax, and the Phase 2 and Phase 3 DOM checks. These are inherited
results from the recorded checkpoint, not a new full-suite run for this report.

A focused additional run passed **14 tests** in 0.91 seconds. It covered threshold
window inclusion/expiry, duplicate suppression, initial partial-batch read
baseline, later unread metadata, restart persistence, explicit read versus review,
saved custom intervals, and per-alert review/reset behavior. These used controlled
fixtures, temporary stores, and fake notification adapters. They are **synthetic
software tests**, even where a fixture sets `synthetic=false` to exercise the live
storage contract. They did not generate real Windows security events or display
native notifications.

The selected test functions were:

- `tests/test_engine.py`: `test_window_boundary_and_evidence_are_inclusive`,
  `test_expired_event_does_not_satisfy_threshold`,
  `test_duplicate_id_cannot_manufacture_a_burst`.
- `tests/test_notifications.py`:
  `test_first_partial_batch_is_read_then_new_alert_is_unread_and_attempted_once`,
  `test_restart_preserves_unread_claim_and_review_without_repeating`,
  `test_http_read_is_explicit_idempotent_and_separate_from_review`.
- `tests/test_preferences.py`:
  `test_preferences_survive_restart_and_custom_interval`.
- `tests/test_reviews.py`: `test_review_updates_and_reset_apply_only_to_one_alert`.

## Actual read-only Windows source check

One `collect_windows(since, limit=200)` call used a UTC cutoff 24 hours before
the probe began. It ran as the existing account with Python 3.14.8 on Windows.
The collection completed on 2026-11-05 at approximately 23:08:55 UTC
(2026-11-06 02:08:55 Europe/Istanbul).

| Channel | Status | Selected observations | Cap reached | Error code |
| --- | --- | ---: | --- | --- |
| System | `ok` | 55 | No | None |
| Security | `unavailable` | 0 | No | `permission_denied` |
| Microsoft-Windows-Windows Defender/Operational | `ok` | 0 | No | None |

All three expected channel results were present. Two channel queries were accessible;
one channel was unavailable, with no reported collection error or result cap.
The monitor exposed `health.status=partial`, `sources_ok=2`,
`sources_unavailable=1`, and `source_results_current=true`.

The accessible empty Defender result means no selected matching records were
returned for this query. The unavailable Security result establishes no absence
of activity. This bounded snapshot does not prove complete auditing, continuous
coverage, or future access. Channel settings, existing retention and selected
event families still constrain coverage; see [Windows monitoring](windows-monitoring.md).

## Normalization, store, and evidence checks

The actual batch contained 55 non-synthetic `windows-eventlog` observations.
Schema normalization round trips, chronological order, unique normalized IDs,
allowlisted attribute names, and agreement between per-source and total counts
passed without publishing individual records.

The captured batch was reused in memory by a temporary `LiveMonitor` and schema-2
`EventStore`, with `notifier=None`. Replaying that same batch left **55 events and
3 alerts**, without duplicate insertion. All three historical rule alerts had
complete evidence links, and each linked event passed normalization again.
Rule matches alone do not establish malicious activity or an incident.

Reopening the temporary store, rebuilding rule state, and replaying the same
captured batch retained the 55 events and 3 alerts. Existing alert payload and
evidence bytes were unchanged. Initial history and restart replay remained read
(`unread_count=0`), native availability was false, and no native attempt occurred.
There were no late events in this batch. Replay stability is not an independent
second Windows collection or a long-running polling test.

## Procedure and privacy

The local probe called the existing collector once, inspected normalized objects
in memory, and exercised application persistence in a new temporary directory
under the parent workspace's private `work/v0.4-readonly-validation` directory,
outside the Git checkout. It did not open the GUI, start background monitoring,
use an existing Sentinel database, change Windows permissions or configuration,
request elevation, install a service, alter auditing/log channels/Defender, or
generate authentication failures or other artificial security activity.

Only the probe and aggregate provenance/results remain locally in that private
directory. The temporary store containing real observations was closed and
removed after validation. No raw capture/export was saved or uploaded. The
committed report contains aggregate counts and channel/error status only; it
omits account/device names, record identifiers, local private paths, and event or
evidence payloads. Synthetic-test temporary data contains fixtures only.

For another check, choose a new private directory outside the checkout, record the
source revision, runtime, timestamp, query bounds and channel statuses, and retain
only the minimum metadata needed. Review local logs/exports before any sharing.
Do not publish real data as a validation fixture or package input.

## Remaining gates and safe manual checklist

These checks remain **unperformed**. They are not replaced by the automated or
current-PC read-only evidence above:

- Controlled real Windows threshold bursts, real log-clear/account/group/service
  scenarios, and channel outage/recovery or cap/stale behavior. Do not manufacture
  these on the current PC; existing synthetic tests cover software behavior only.
- A clean-machine install/portable check without the development environment.
  There is no separate test machine available for this record.
- A real native window, rendering, native Save As interaction, and observed
  notification appearance/suppression/lifecycle behavior.
- RF/embedded hardware or other physical sensor integration.

For the upcoming native package, record each item's actual outcome as pass,
failure, or not exercised; identify it as a current-PC check if that is the only
available environment:

1. Record candidate version, package checksum, and existing runtime availability.
   Extract the complete package and launch normally without elevation or changing
   security/runtime settings. Record missing prerequisites as a limitation.
2. Observe dashboard rendering and honest source health. An inaccessible Security
   channel must remain visibly unavailable; accessible zero counts must remain
   distinguishable from errors. Leave channel settings unchanged.
3. Open existing alert evidence and inspect its explanation. Exercise explicit
   read and review controls separately, checking that review disposition does not
   rewrite evidence. If no suitable alert is present, record not exercised.
4. Save preferences, close normally, and reopen to check persistence. Check that
   historical replay does not create a notification/unread storm. A newly arriving
   alert must be naturally observed or the live unread case stays not exercised.
5. For an operator-exercised notification test, save explicit opt-in and use the
   clearly labeled test control. Record queue/status separately from what actually
   appears on screen. Queue acceptance does not guarantee Windows display; record
   suppression or unavailability truthfully. Do not disable protection or change
   Windows notification settings to force a result.
6. Close the window normally, allow any bounded in-flight collection to finish,
   and verify shutdown and subsequent reopening. Observe resource cleanup; a
   successful fake lifecycle test does not establish native cleanup on this PC.
7. Keep all real local state and exports private. Check package contents separately
   for accidental inclusion of databases, captures, or startup logs, following the
   [desktop guide](desktop.md).

Any unavailable gate must remain stated in release documentation. This record
supports the adjusted read-only validation scope, not a claim that every Windows
scenario or native delivery path has been verified.
