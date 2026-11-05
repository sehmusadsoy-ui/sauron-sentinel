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

## Desktop and portable builds

The standard development environment and test matrix do not require a GUI runtime. Desktop tests should mock the window host and exercise lifecycle, instance locking, data paths, and shutdown. Verify a real Windows launch/close separately before distributing a portable artifact.

On a supported Windows x64 Python environment, install `.[desktop,desktop-build]` and run `python scripts/build_desktop.py`. See the [desktop guide](docs/desktop.md) for the full package layout and system-runtime requirement. Keep the portable build free of live databases, logs, captures, user profiles, and local absolute paths in human-readable manifests/notices. Preserve third-party license notices.

Do not add an installer, autostart behavior, elevation, automatic WebView2 installation, or a remote listener as an incidental packaging change. The existing portable edition does not require those behaviors.

## Data and rule changes

- Use synthetic telemetry in tests and issue reports. Mark it explicitly and avoid secrets or real identifiers.
- Document any event-schema or rule-semantics change, including compatibility effects.
- Keep numeric units explicit in attribute names.
- Preserve deterministic replay and explainable evidence references.
- Treat adapters as separate trust boundaries. A source label alone must never be described as tested hardware integration.
- Keep runtime dependencies and privileges minimal. Discuss new services, listeners, actions, and storage systems before expanding the architecture.

Update the relevant documentation and changelog when behavior changes. MIT licensing applies to contributions included in this project.
