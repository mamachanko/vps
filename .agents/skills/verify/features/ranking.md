# Directory ranking

Find which immediate children of a directory occupy the most disk space.

## Sub-features

- `scan-limit` returns up to the requested number of entries.
- `allocated-bytes` includes descendant allocation and measures sparse files by disk usage.
- `link-accounting` counts shared inodes once and counts symlinks at their own entries.

## How to get to it (user POV)

Run `vps disk PATH --top N` with a directory. Add `--json` for exact byte counts.

## Driving it with verify.py

Use the [baseline preconditions](README.md). The driver seeds a nested file,
hard link, symlink, hidden file, and sparse file in a temporary directory.

```sh
uv run --locked --no-sync python .agents/skills/verify/scripts/verify.py ranking
```

- **Allocation.** `vps disk PATH --top 5 --json` exits `0`. The report orders all five fixture entries by allocated bytes, then name. The hard link contributes zero extra bytes.
- **Limit.** `vps disk PATH --top 1` exits `0` and displays one row for the largest entry. The fixture contents, names, and links are intact.

## Gotchas

Use the fixture filesystem's allocated blocks to calculate expected bytes.
Allocation can vary across filesystems even when file contents match.
