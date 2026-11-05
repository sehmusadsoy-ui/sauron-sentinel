# Detection rules

Rules are declarative TOML. They compare existing fields and count matching events in event-time windows. No rule executes Python, shell commands, network requests, or response actions.

```toml
schema_version = 1

[[rules]]
id = "auth-failure-burst"
title = "Repeated authentication failures"
severity = "medium"
kind = "auth.failure"
threshold = 5
window_seconds = 60
cooldown_seconds = 60
group_by = ["device_id", "attributes.user"]
```

Run a file with a custom ruleset:

```sh
sauron-sentinel run --input examples/telemetry.jsonl --rules examples/custom-rules.toml --output custom-output
```

## Rule fields

| Field | Meaning |
| --- | --- |
| `id` | Unique stable identifier |
| `title` | Human-readable alert title |
| `severity` | `low`, `medium`, `high`, or `critical`; an author-assigned priority |
| `kind` | Exact event kind to consider |
| `threshold` | Number of matching events required; default `1` |
| `window_seconds` | Inclusive sliding event-time window; default `60` |
| `cooldown_seconds` | Minimum time between alerts for the same group; default `60` |
| `group_by` | Fields that define an independent counter; default `["device_id"]` |
| `conditions` | Additional comparisons; every condition must match |

Configuration validation rejects unknown fields, duplicate rule IDs, unsupported operators, invalid scalar values, and values outside bounds. A rules file is at most 256 KiB and must contain 1–64 rules. Thresholds are integers from 1 through 10,000; windows are greater than zero and at most 86,400 seconds; cooldowns range from zero through 86,400 seconds. A rule can group on 1–8 unique fields and contain at most 16 conditions.

## Conditions

```toml
[[rules]]
id = "strong-rf-observations"
title = "Cluster of strong RF observations"
severity = "low"
kind = "rf.observation"
threshold = 3
window_seconds = 10
cooldown_seconds = 30
group_by = ["device_id"]
conditions = [{field = "attributes.rssi_dbm", op = "gte", value = -40}]
```

Supported fields are `source`, `kind`, `device_id`, `synthetic`, and `attributes.<key>`. Supported operators are `eq`, `ne`, `gt`, `gte`, `lt`, and `lte`. Numeric ordering uses finite numbers and does not coerce strings or booleans into numbers. Equality/inequality compare compatible types; both reject mismatched types rather than treating them as a match. Integer and floating-point numbers are compatible, while booleans are distinct. Missing fields do not satisfy conditions. Grouping requires the selected fields to exist.

The synthetic flag is always included in the grouping boundary, even if omitted from `group_by`. Real and simulated observations cannot combine to meet a threshold.

## Time and evidence semantics

- The window is inclusive: an event exactly `window_seconds` before the current event can contribute.
- The engine uses event timestamps, not replay speed or the machine's current clock.
- Input must be globally ordered. An event older than the accepted watermark is rejected.
- After an alert, matching events can continue to update evidence while alerts for that group are suppressed by the cooldown.
- At the exact end of a cooldown, a qualifying event can produce a new alert.
- Evidence is bounded to the most recent `threshold` matching events. `matched_count` reports that retained evidence count.
- Duplicate event IDs in the bounded deduplication cache do not contribute twice. The cache is not permanent and does not survive a new run.

## Windows baseline rules

The bundled rules also include `windows-service-installed`, `windows-log-cleared`, `windows-defender-threat`, `windows-defender-disabled`, `windows-account-created`, `windows-group-member-added`, and `windows-unexpected-shutdown`. Each matches one corresponding Windows event kind, has a threshold of one, and uses a zero-second cooldown. Severity is medium for service/account/group/shutdown observations and high for log-clearing/Defender threat/disable observations.

These are investigation prompts. Legitimate service installation, administration, or an operational crash can trigger them. The existing `auth-failure-burst` rule considers repeated `auth.failure` records only when the Security source supplies them; inaccessible Security logs do not imply an absence of authentication failures.

Live monitoring retains newly discovered out-of-order events in the timeline immediately, skips them during the current live alert pass, and reports a late-event count. Restart/recovery replay processes retained records chronologically and can therefore add historical alerts from late records. Existing alert IDs are preserved rather than overwritten. Batch analysis continues to reject out-of-order input. See the [architecture](architecture.md).

## Explanation catalog

The Turkish evidence view has a schema-1 explanation for each of the ten bundled rule IDs. It presents matching conditions, possible benign causes, and safe read-only checks separately from the raw alert/evidence. This catalog does not establish intent, current Defender status, file trust, group privilege, or sensor authenticity. Unknown/custom IDs receive cautious generic guidance rather than invented conditions.

| Rule ID | Match and possible benign context | Safe check |
| --- | --- | --- |
| `auth-failure-burst` | At least 5 failures for one device/user in 60 seconds; 60-second cooldown. A mistyped or outdated saved password can explain a burst. | Compare user/times with known login attempts and inspect Event Viewer. |
| `rf-activity-burst` | At least 3 numeric RSSI values ≥ −40 dBm for one device in 10 seconds; 30-second cooldown. Normal nearby transmitters or sample generation can explain the data. | Inspect provenance, synthetic flag, units, and capture conditions; infer no physical device or intent from this example. |
| `motion-without-maintenance` | One numeric score ≥ 0.8 with Boolean maintenance=false; 30-second window and 60-second cooldown. Normal motion, noise, or an incorrect maintenance field can explain it. | Inspect how the producer generated the score and maintenance field; make no physical-security decision from the score alone. |
| `windows-service-installed` | One service-install record. Software, driver, update, or authorized maintenance can cause it; the rule does not inspect signatures or paths. | Compare time/name/path with known installations and read file publisher/service properties. |
| `windows-log-cleared` | One log-clear record. Authorized maintenance or planned log management can cause it. | Compare log/time/actor with maintenance records; preserve the remaining logs. |
| `windows-defender-threat` | One Defender detection record. It may be a false positive, test item, or already-blocked/quarantined item; subsequent action is not verified. | Read Protection History and the recorded action without running the file. |
| `windows-defender-disabled` | One protection-disable record. Authorized maintenance, another security product, or managed policy can explain it; current protection state is unknown. | Read current Windows Security status and compare the time with authorized maintenance/policy. |
| `windows-account-created` | One account-create record. Application/service setup or authorized provisioning can cause it. | Compare name/time/actor with known setup and read account properties. |
| `windows-group-member-added` | One local security-group membership record. Authorized access changes or policy application can cause it; the rule does not assess the group's privilege. | Read group/member details and compare current membership with expected access. |
| `windows-unexpected-shutdown` | One unexpected-shutdown record. Power loss, a forced shutdown, crash, driver, or hardware fault can explain it. | Compare the time with known interruptions and read Reliability History/Event Viewer. |

RF and motion are offline schema demonstrations. Live Windows monitoring does not acquire RF, CSI, motion, Flipper Zero, or ESP32 data. RF Canvas, CSI Radar, and LabMate integrations remain planned only.

## Human review and unread state

A local review applies to one alert ID: `new`, `reviewed`, or `expected`, with an optional note and update timestamp. Resetting a review to `new` is allowed. This metadata persists without modifying the stored alert payload or evidence; marking expected does not allowlist a rule or suppress future similar events. Explanation text is also separate from evidence.

Notes allow at most 500 Unicode code points. Validation rejects Unicode control (`Cc`), format (`Cf`), and surrogate (`Cs`) characters, except newline and tab. The review endpoint accepts a UTF-8 JSON object with exactly `status` and `note`, rejects duplicate keys, and limits the request body to 8,192 bytes. Text is rendered as text, not HTML. Retention removes a review when its alert is pruned.

Unread is a separate persistent flag. An evidence GET does not change it; after evidence loads successfully, the dashboard explicitly posts an idempotent read update. A review save does not mark read. Initial/historical/replay alerts remain read; newly inserted eligible live alerts become unread whether or not Windows notifications are enabled. Notification eligibility and display do not prove an incident or establish that a person reviewed it.

## Calibration

The default rules are educational baselines. Authentication failures can be user error; strong RF observations can be normal transmitters; motion can be expected activity. Establish ground truth, compare against benign captures, measure false positives, and tune thresholds before relying on a rule operationally. Version the exact ruleset with each experiment.
