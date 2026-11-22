---
name: verify
description: Verify vps through its installed command. Use after changes to disk capacity, directory ranking, scan status, or the Linux hardening audit.
---

# Verify vps

## Launch

On Linux or macOS, run `uv sync --locked` from the vps repository root.
Each drive starts a fresh CLI process from the checkout's uv environment. The
driver creates its own temporary fixtures. There is no server or persistent
test data to initialize.

## Doctor

Run the doctor after syncing or when a drive fails to start.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py doctor
```

`PASS doctor` means the installed version matches `pyproject.toml` and the
installed `disk --help` exposes `--top` and `--json`.

## Drive

Select the journeys for the change in the [feature map](features/README.md).
For example, run the scan status journey after a terminal change.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py progress
```

The driver launches the installed `vps` entry point. The status journey
attaches a pseudo-terminal to stderr and captures stdout independently.
For rechecking the full disk command, run the four mapped journeys.

```sh
(
  set -e
  for journey in capacity ranking progress errors; do
    uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py "$journey"
  done
)
```

## Evidence

Open the `vps-evidence-*` directory printed by each invocation. Read
`run.json` for the journey, fixture path, and verdict. Each recorded command
has a `.json` file with the arguments, working directory, terminal mode, and
exit code, plus raw `.stdout` and `.stderr` files.

Check the command, streams, and exit code together. For read-only disk scans,
check the fixture after the command and confirm that its contents and links
still match. For the terminal journey, keep the raw stderr bytes so they show
both the status and the cursor restoration. Report any failed precondition
with the attempted journey and its evidence directory.

## Cleanup

The driver closes the terminal, waits for the process it started, and removes
its fixture on exit. Confirm the fixture path in `run.json` is gone and retain
the evidence directory. That directory is separate from the fixture and
survives cleanup. Each invocation creates both directories independently.

## Helpers

[verify.py](scripts/verify.py) accepts `doctor`, `capacity`, `ranking`,
`progress`, `errors`, `audit`, and `audit-fast`. Run it through the checkout's
uv environment as shown above. The `audit` journey uses installed OpenSCAP
and supports `--oscap`, `--datastream`, and `--profile`. The driver exits `1`
when an expected result or precondition fails.
