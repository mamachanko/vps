# Security audit

Check the hardening baseline of the Linux VPS where `vps` runs.

## Sub-features

- `audit-report` shows a verdict, prioritized findings, evidence, and next steps.
- `audit-json` exposes the same finding statuses and report scope.
- `audit-platform` gives a Linux requirement on unsupported systems.

## How to get to it (user POV)

Run `vps audit` for the terminal report or `vps audit --json` for automation.

## Driving it with verify.py

Use the [baseline preconditions](README.md). Run this journey from the repository root.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py audit
```

- **Linux JSON.** The report lists all five baseline checks in priority order. Its counts and exit code agree with the findings and verdict.
- **Linux terminal.** The report shows `VPS security audit` and its scope. The stderr transcript shows the status message and cursor restoration.
- **Unsupported platform.** The command exits `2` with a Linux requirement on stderr and empty stdout.

## Gotchas

The command reads the host it runs on. Probe results vary with local
permissions, packages, and configuration. Treat an unverified row as an
observed result with a next step. A macOS run covers the platform diagnostic.
