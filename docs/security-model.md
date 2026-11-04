# Security model

## Intended environment

The first release is a local tool for controlled experiments with telemetry the operator is authorized to process. It is not a hardened multi-tenant service or an evidence custody system. No process privileges beyond ordinary local file access should be necessary.

## Assets and trust boundaries

The principal assets are the operator's telemetry, prior run output, and confidence in how an alert was produced. JSONL records and TOML configuration are untrusted data. Producer labels and synthetic flags are claims rather than authenticated identities.

| Risk | Implemented control | Remaining limitation |
| --- | --- | --- |
| Ambiguous or malformed input | Strict fields, scalar validation, duplicate-key and non-finite rejection | Malicious but valid data can still mislead a heuristic |
| Resource exhaustion | Bounded line length, event count, rules, threshold evidence, groups, and deduplication | Use OS/process limits for hostile workloads; disk usage grows with accepted records |
| Code execution through rules | Fixed comparison operators; no `eval`, shell actions, or plugins | Future adapters must preserve this boundary |
| Overwriting prior evidence | A new output directory is required | An operator can still alter or delete files afterward |
| Exposure through a service | No listener or automatic outbound upload | Files inherit the local machine's access controls |
| Simulation contaminating live counts | Synthetic and real grouping separation | The producer can lie about the flag |
| Replay inflation | Deterministic IDs and bounded duplicate suppression | Replays outside the cache or across runs are not globally suppressed |
| Clock ambiguity | Explicit timezone required and out-of-order events rejected | Device clock correctness is not verified |

## Privacy and output handling

Normalized records preserve accepted attribute values. Sentinel does not automatically redact usernames, addresses, identifiers, or secrets. Do not feed credentials or unnecessary personal data into a shared run. Output files are plaintext and have no application-managed encryption, signatures, or retention policy. Store them in a directory with suitable local access controls and remove them when no longer needed.

The bundled demonstration is synthetic. It should be used for issue reports and reproducible examples in place of real captures.

## Detection limits

An alert records a rule match, not a verified incident. No rule can establish RF attack intent or physical presence from these sample attributes alone. Severity is set by the rule author. There is no automatic remediation or active radio behavior.

No empirical false-positive rate or detection accuracy is claimed. Such a claim would require labeled controlled captures and an evaluation protocol that this release does not include.

## Supply chain

The installed runtime has no third-party dependencies. Build and development tools are pinned at the top level in `pyproject.toml`; their transitive dependencies are not locked. GitHub Actions are pinned to full commit IDs, use read-only repository permissions, and do not retain checkout credentials. CI does not require user-supplied secrets or publish to a package registry.

See [SECURITY.md](../SECURITY.md) for responsible reporting.
