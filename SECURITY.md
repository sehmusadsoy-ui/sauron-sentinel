# Security policy

Sauron Sentinel is an early local-analysis tool. Security fixes target the latest release and the `main` branch; older versions do not have a separate maintenance guarantee.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/sehmusadsoy-ui/sauron-sentinel/security/advisories/new) if it is enabled for this repository. If it is unavailable, open a minimal issue asking for a private reporting channel without including exploit details, real telemetry, personal information, or secrets.

Include the affected version, Python and operating-system versions, expected and actual behavior, and a minimal synthetic reproducer. Do not publish sensitive captures or run tests against systems without permission. No response-time guarantee or bug-bounty program is offered.

## Scope and safe use

The runtime reads local files or standard input and writes local reports. It does not implement active scanning, RF transmission, hardware collectors, or automatic remediation. A matched rule is an observation to investigate, not proof of an attack.

Outputs contain plaintext attributes as supplied. Choose access-controlled storage and redact data before sharing. The [security model](docs/security-model.md) explains trust boundaries and remaining limitations.
