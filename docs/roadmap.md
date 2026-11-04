# Roadmap

This document separates shipped behavior from proposals. Milestones are acceptance criteria, not commitments or compatibility claims.

## 0.1 — Local telemetry foundation

Implemented in this repository:

- Streaming JSONL ingestion and strict, versioned normalization.
- Deterministic event references and local evidence output.
- Declarative event-time detection with bounded state and cooldowns.
- Synthetic demo data, automated tests, package build checks, and Windows/Linux CI.

## Next — Adapter contracts and controlled captures

Proposed targets are RF Canvas, CSI Radar, and LabMate, involving Flipper Zero and ESP32 where applicable. No integration is complete.

An adapter is ready only when it has:

1. A documented export/transport protocol and supported firmware versions.
2. Bounded framing, reconnect/error handling, and explicit device identity.
3. Clock synchronization and a declared late-event policy.
4. Attribute units, producer version, calibration metadata, and provenance rules.
5. Controlled real captures labeled separately from synthetic fixtures.
6. Integration tests using those captures and an end-to-end hardware validation procedure.

Passive acquisition should remain separate from detection. Any operation that can transmit, change device configuration, or interact with a network requires its own deliberate interface and authorization model.

## Later — Investigation and evaluation

- A local timeline viewer with event and alert filters, evidence navigation, and explicit partial-run status.
- Reproducible labeled lab scenarios, false-positive analysis, and throughput measurements with disclosed hardware and inputs.
- Durable deduplication and retention policies when the storage model needs them.
- Cross-source correlation only after clock, device identity, and provenance contracts are validated.
- Optional operating-system telemetry exporters with dedicated tests and documented platform support.

## Further research

Threat-intelligence enrichment, Sigma interoperability, statistical anomaly detection, and a dashboard may be useful future work. None is implemented or claimed by v0.1.0. They should be introduced only with clear data boundaries, repeatable validation, and a maintenance plan.
