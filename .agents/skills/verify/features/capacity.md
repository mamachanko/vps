# Filesystem capacity

Check the size, used space, and available space for the filesystem containing a path.

## Sub-features

- `default-filesystem` reports the filesystem containing `/`.
- `file-capacity` reports the filesystem containing a file.
- `capacity-json` exposes exact byte counts.

## How to get to it (user POV)

Run `vps disk` or pass a file to `vps disk PATH`. Add `--json` for machine output.

## Driving it with verify.py

Use the [baseline preconditions](README.md). Run this journey from the repo root.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py capacity
```

- **Default path.** `vps disk --json` exits `0`. Stdout reports `/`, filesystem totals, and `scan: null`.
- **File path.** `vps disk PATH` exits `0`. The terminal report shows the temporary file path and available space. The file contents are intact.

## Gotchas

Free space can change while verification runs. Compare the filesystem total
and the arithmetic within one report.
