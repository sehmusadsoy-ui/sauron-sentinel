# Event data contract

Input is UTF-8 JSON Lines: one JSON object per line. Keep the stream globally ordered by timestamp. Every event must explicitly state whether it is synthetic.

```json
{"schema_version":1,"timestamp":"2026-01-01T12:00:00Z","source":"lab-demo","kind":"auth.failure","device_id":"demo-host","synthetic":true,"attributes":{"user":"demo-user","remote_ip":"192.0.2.10"}}
```

The example uses an address reserved for documentation and carries no real credentials or personal data.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | Integer | Must be `1` |
| `timestamp` | String | `YYYY-MM-DDTHH:MM:SS[.ffffff](Z\|±HH:MM)`; optional fraction has 1–6 digits |
| `source` | String | Producer label; not a verified identity |
| `kind` | String | Event type such as `auth.failure`, `rf.observation`, or `motion.observation` |
| `device_id` | String | Stable device label chosen by the producer |
| `synthetic` | Boolean | Explicitly marks demonstration/simulated data |
| `attributes` | Object | Flat named JSON scalars used as evidence and rule input |

The timestamp uses uppercase `T` and `Z`, seconds are required, and a UTC offset is mandatory. Fractions longer than six digits are rejected instead of truncated. Examples are `2026-01-01T12:00:00Z`, `2026-01-01T15:00:00.123456+03:00`, and `2026-01-01T07:00:00-05:00`.

`event_id` is optional on input. If supplied, it must match the ID derived from normalized content; this allows replay of `events.jsonl`. Other unknown top-level fields are rejected. Attributes must be flat: nested objects and arrays are not supported. Attribute values can be strings, finite numbers, booleans, or null. Booleans are not accepted as numeric substitutes. Duplicate JSON keys and non-finite values (`NaN`, infinities) are rejected.

The collector bounds each line to 65,536 bytes including line endings. Blank lines are ignored. The normalizer applies these additional constraints:

| Value | Constraint |
| --- | --- |
| `source`, `kind` | 1–64 characters; lowercase letter first, then lowercase letters, digits, `_`, `.`, `-` |
| `device_id` | 1–128 characters; letter or digit first, then letters, digits, `_`, `.`, `:`, `-` |
| Attribute count | At most 32 |
| Attribute names | 1–64 characters; letter or `_` first, then letters, digits, `_` |
| Attribute strings | At most 1,024 characters |
| Attribute integers | −(2^53−1) through 2^53−1 |

These limits are part of the validation boundary; do not rely on truncation to make an event acceptable.

## Normalized records

Normalization converts timestamps to UTC with six-digit microsecond precision and adds a deterministic SHA-256 `event_id` derived from canonical event content. Equivalent timezone representations normalize to the same timestamp and identity. The normalized event log preserves the validated attributes and synthetic flag. Repeated observations remain visible in this log; deduplication suppresses their contribution to detections within the engine's bounded cache.

Content identity is not a signature. Neither the hash nor the `source`, `device_id`, or `synthetic` field verifies the producer's claims.

## Output files

This section describes `run` and `demo` batch output. Browser/CLI live monitoring defaults to `sentinel-data/sentinel.db`; desktop mode uses its separate `%LOCALAPPDATA%\SauronSentinel` directory. Both persist retained events, alerts, and evidence snapshots. `collect-windows` writes an event snapshot and a summary with per-channel availability.

| File | Contents |
| --- | --- |
| `events.jsonl` | Accepted normalized telemetry records, one object per line |
| `alerts.jsonl` | Rule alerts with severity, event-time window, grouping values, and contributing event IDs |
| `summary.json` | `schema_version`, package `version`, `status`, `events_processed`, `synthetic_events`, and `alerts_emitted`; an `error` field on a processing failure |

An alert's `event_ids` link back to normalized events, allowing a reviewer to inspect the evidence. Its `window_start` and `window_end` describe the span of the retained evidence, rather than a fixed-duration interval. `matched_count` describes retained threshold evidence, not a count of every matching event over an unlimited stream.

The output directory must not already exist. A processing failure may leave partial files for inspection; a nonzero command result means the run must not be treated as complete. Keep incomplete output separate from successful evidence exports.

## Live local metadata

Live state and JSON exports add `review` and `unread` to alert presentation objects. A review contains `status` (`new`, `reviewed`, or `expected`), `note`, and nullable `updated_at`; unread is an independent Boolean. These fields are local operator metadata, not normalized event attributes or rule input. Batch alert output and stored raw alert/evidence payloads are unchanged. The evidence endpoint returns the raw `alert` and `events` alongside separate `explanation`, `review`, and `unread` fields; reading it alone does not mark an alert read.

Live export also includes local monitor/source health, preferences, and notification-attempt state. It is a bounded retained snapshot (up to 10,000 events and 2,000 alerts), not a complete audit archive or proof of native delivery. Notes and event context can be sensitive plaintext. See [rules](rules.md) for review bounds and [architecture](architecture.md) for schema-2 storage/migration and retention semantics.

## Producer guidance

- Use UTC at the source when possible, and synchronize device clocks before merging streams.
- Define units in attribute names, for example `rssi_dbm`.
- Treat `motion_score` as a producer-defined score. Sentinel does not compute or calibrate CSI features.
- Export only the attributes needed for the experiment. No automatic redaction is performed.
- Set `synthetic=true` on simulations. Keep documentation fixtures separate from real lab captures.
- Give each observation a distinct timestamp or distinct content when it represents a separate physical event; identical content is intentionally deduplicated within the bounded cache.

## Windows source mapping

The Windows collector emits `source=windows-eventlog`, a stable `windows-<16 hex characters>` device pseudonym, and `synthetic=false`. Attributes identify the original `channel`, `provider`, Windows `event_id`, and `record_id`. The top-level `event_id` remains Sentinel's normalized SHA-256 content identifier and is distinct from the numeric Windows event ID stored in attributes.

Allowlisted context fields can include `user`, `target_user`, `logon_type`, `group_name`, `service_name`, `service_type`, `start_type`, `old_start_type`, and `threat_name`. Strings are capped to 256 characters with `fields_truncated=true` when applicable. Full raw XML and rendered event messages are not persisted. These limits reduce collection volume; selected values can still be sensitive.

See [Windows monitoring](windows-monitoring.md) for selected event IDs, source status, and coverage limits.
