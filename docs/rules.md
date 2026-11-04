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

## Calibration

The default rules are educational baselines. Authentication failures can be user error; strong RF observations can be normal transmitters; motion can be expected activity. Establish ground truth, compare against benign captures, measure false positives, and tune thresholds before relying on a rule operationally. Version the exact ruleset with each experiment.
