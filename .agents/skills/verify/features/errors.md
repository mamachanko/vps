# Errors and partial results

An inspection can fail before producing a report or return a partial ranking
when it cannot inspect a child.

## Sub-features

- `missing-path` reports a fatal filesystem error.
- `invalid-scan-target` rejects a file passed to `--top`.
- `unreadable-child` retains readable entries and reports the failed child.

## How to get to it (user POV)

Pass a missing path to `vps disk`, a file to `vps disk PATH --top N`, or a
directory with an unreadable child to `vps disk PATH --top N --json`.

## Driving it with verify.py

Use the [baseline preconditions](README.md). The partial scan requires a
user whose access the fixture directory's permissions can restrict.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py errors
```

- **Missing path.** `vps disk PATH --json` exits `1` with an error on stderr and empty stdout.
- **Invalid target.** `vps disk PATH --top 1 --json` on a file exits `2` with a directory diagnostic and empty stdout.
- **Partial scan.** Scan a directory that contains a readable file and an unreadable child directory. Exit `3` preserves JSON stdout with the readable entry and the issue path. Stderr reports the partial scan.

## Gotchas

Root privileges can bypass the permission denial. Run this journey as an
unprivileged user. The driver restores the fixture permissions before cleanup.
