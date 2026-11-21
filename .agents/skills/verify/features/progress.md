# Scan status

During a directory scan, the terminal shows that `vps` is still working.

## Sub-features

- `interactive-scan` displays a spinner on interactive stderr.
- `redirected-scan` keeps redirected stderr quiet on success.
- `status-cleanup` clears the status when the scan exits.

## How to get to it (user POV)

Run `vps disk PATH --top N` with stderr attached to a terminal. The status is
also visible when you pass `--json` and redirect stdout only.

## Driving it with verify.py

Use the [baseline preconditions](README.md). The driver gives stderr a
pseudo-terminal and verifies both streams independently.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py progress
```

- **Interactive stderr.** `vps disk PATH --top 1 --json` exits `0`. The transcript records `Scanning disk usage...`, a line clear, and cursor restoration. Stdout parses as the fixture report.
- **Redirected stderr.** The same command exits `0` with empty stderr and valid JSON.
- **Capacity check.** `vps disk PATH --json` with terminal stderr exits `0` with empty stderr and `scan: null`.
- **Failed scan.** Pass a missing path to `vps disk PATH --top 1 --json`. It exits `1`, restores the cursor, and prints a diagnostic on stderr.

## Gotchas

The status is transient. Inspect the raw stderr transcript to see output
that the terminal cleared. A redirected session cannot prove terminal behavior.
