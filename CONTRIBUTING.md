# Contributing

Contributions should keep the first release easy to inspect and reproduce. Prefer a focused change with a small synthetic input that demonstrates the behavior.

## Set up

Use Python 3.11 or newer and an isolated environment:

```sh
python -m venv .venv
# Activate .venv using your shell's normal command.
python -m pip install -e ".[dev]"
```

Before submitting:

```sh
python -m ruff check .
python -m ruff format --check .
python -m pytest --cov --cov-report=term-missing
python -m build
```

Tests should cover an observable behavior or a trust boundary. Include negative inputs for schema or rule changes. Do not lower the coverage gate to conceal an untested failure path.

## Data and rule changes

- Use synthetic telemetry in tests and issue reports. Mark it explicitly and avoid secrets or real identifiers.
- Document any event-schema or rule-semantics change, including compatibility effects.
- Keep numeric units explicit in attribute names.
- Preserve deterministic replay and explainable evidence references.
- Treat adapters as separate trust boundaries. A source label alone must never be described as tested hardware integration.
- Keep runtime dependencies and privileges minimal. Discuss new services, listeners, actions, and storage systems before expanding the architecture.

Update the relevant documentation and changelog when behavior changes. MIT licensing applies to contributions included in this project.
