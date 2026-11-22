# Security audit

Check the hardening baseline of the Linux VPS where `vps` runs.

## Sub-features

- `audit-report` shows the OpenSCAP verdict, coverage, and prioritized findings.
- `audit-json` exposes the evaluated profile and all selected rule results.
- `audit-fast` reports five local checks and preserves their JSON contract.
- `audit-platform` gives a Linux requirement on unsupported systems.

## How to get to it (user POV)

Run `vps audit` for the terminal report or `vps audit --json` for automation.
Add `--fast` to run the five local checks.

## Driving it with verify.py

Use the [baseline preconditions](README.md). Run this journey from the repository root.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py audit
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py audit-fast
```

- **OpenSCAP.** Install the scanner and matching data stream first. The journey accepts `--oscap`, `--datastream`, and `--profile`. The report identifies the scanner and profile. Its counts and exit code agree with the findings and verdict.
- **Quick check.** The JSON report lists five checks in priority order. The terminal report shows `VPS quick audit` and the local scope.
- **Terminal status.** In both journeys, the stderr transcript shows the status message and cursor restoration.
- **Unsupported platform.** The command exits `2` with a Linux requirement on stderr and empty stdout.

## Gotchas

The command reads the host it runs on. Probe results vary with local
permissions, packages, and configuration. Read unverified results alongside
the reported scan privileges. A macOS run covers the platform diagnostic.
