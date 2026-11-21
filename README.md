# vps

`vps` is a read-only command-line utility for Unix servers. Use it to check how
much space a filesystem has left and find the largest entries in a directory.

## Run from a checkout

Use [uv](https://docs.astral.sh/uv/) on Linux or macOS with Python 3.11 or newer.
Run these commands from the repository root.

```sh
uv sync --locked
uv run vps disk
uv run vps disk /var --top 10
uv run vps disk /var --top 10 --json
```

To install the command on your PATH, run `uv tool install .` from the checkout.
Run `vps --help` or `vps disk --help` for command options.

## Disk usage

`vps disk [PATH]` reports capacity for the filesystem containing `PATH`.
The default path is `/`. You can pass a file or a directory. The capacity
report includes space reserved from
ordinary users where the filesystem exposes it. The usage percentage compares
used space with the sum of used and user-available space, as in `df`.

`--top N` scans a directory and ranks up to `N` of its immediate children.
Each row includes the allocated disk space for that entry and its descendants.
This measures the space a sparse file occupies on disk. The scan includes
hidden entries and skips entries on other devices. You can pass a symlink as
the root path. Inside the tree, the scan counts the space occupied by each
symlink itself. When multiple names share an inode, the first top-level
entry by name gets credit for the allocation.

## Machine output

`--json` writes one report to stdout and sends diagnostics to stderr.
Sizes are integer bytes and `path` is absolute.

| Field | Meaning |
| --- | --- |
| `schema_version` | Report schema version. Currently `1`. |
| `path` | Requested path. |
| `filesystem` | `total_bytes`, `used_bytes`, `available_bytes`, `reserved_bytes`, and `used_percent`. |
| `scan` | `null` without `--top`. Otherwise contains ranked `entries`, `skipped_other_devices`, `issue_count`, and `issues`. |

Each scan entry has a `name` and `allocated_bytes`. Each issue sample has a
`path` and `message`. The report includes up to five issue samples.

| Exit code | Meaning |
| --- | --- |
| `0` | Complete report. |
| `1` | Inspection failed. |
| `2` | Invalid command arguments. |
| `3` | The scan skipped entries it could not inspect. The report contains partial results. |

## Development

See [AGENTS.md](AGENTS.md) for module boundaries and local checks. GitHub Actions
runs lint, format, tests, and packaging checks on Linux and macOS.
