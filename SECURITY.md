# Security policy

Sauron Sentinel is an early local-analysis tool. Security fixes target the latest release and the `main` branch; older versions do not have a separate maintenance guarantee.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/sehmusadsoy-ui/sauron-sentinel/security/advisories/new) if it is enabled for this repository. If it is unavailable, open a minimal issue asking for a private reporting channel without including exploit details, real telemetry, personal information, or secrets.

Include the affected version, Python and operating-system versions, expected and actual behavior, and a minimal synthetic reproducer. Do not publish sensitive captures or run tests against systems without permission. No response-time guarantee or bug-bounty program is offered.

## Scope and safe use

The runtime reads selected local Windows Event Logs or JSONL input. Live monitoring stores bounded SQLite history and exposes a dashboard exclusively on IPv4 loopback (`127.0.0.1`). It does not support LAN/public deployment, active scanning, RF transmission, embedded hardware collectors, or automatic remediation. A matched rule is an observation to investigate, not proof of an attack.

The local dashboard has no account authentication or TLS and assumes a trusted workstation. Host/Origin checks and a session token protect browser boundaries; other local software/users may still access data. Do not forward its port or place it behind a public proxy.

Databases, evidence, and exports contain plaintext telemetry. Windows collection selects limited fields, but account/service names and threat labels can still be sensitive. Choose access-controlled storage, keep real captures out of Git, and review exports before sharing. The [security model](docs/security-model.md) explains trust boundaries and remaining limitations.
