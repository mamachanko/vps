# vps

`vps` is a read-only command-line utility for Unix servers. Check disk usage
or review the hardening baseline on a Linux VPS.

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

## Disk JSON output

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

## Security audit

Run the audit on the Linux VPS you want to check.

```sh
uv run vps audit
uv run vps audit --json
```

The report puts fixes first. Review items need a judgment about the host's
intended setup. Unverified items show where the audit needs more evidence.
Each finding shows what the audit observed and includes a next step where
one applies.

| Check | Evidence |
| --- | --- |
| SSH root and password login | Global OpenSSH settings from `sshd -T`. |
| Network listeners | Local TCP and UDP sockets bound beyond loopback. |
| Inbound firewall | Live nftables default-drop input policy for IPv4 and IPv6. |
| Automatic updates | Effective APT unattended-upgrade schedule, where available. |

The audit runs locally with your current permissions. Check the provider
firewall and SSH `Match` overrides separately. Review the installed security
updates and recent update runs on the host. Keep a working login or provider
console open while you validate SSH or firewall changes. [OpenSSH server guide](https://ubuntu.com/server/docs/how-to/security/openssh-server/) · [nftables policies](https://netfilter.org/projects/nftables/manpage.html) · [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/)

`--json` writes a versioned report with the verdict, counts by status, and
findings. Each finding has an ID, title, status, evidence, and optional hint.

| Exit code | Meaning |
| --- | --- |
| `0` | All baseline checks passed. |
| `1` | At least one finding needs a fix or review. |
| `2` | Invalid arguments or unsupported platform. |
| `3` | The audit could not verify at least one check. All observed checks passed. |

## Development

See [AGENTS.md](AGENTS.md) for module boundaries and local checks. GitHub Actions
runs lint, format, tests, and packaging checks on Linux and macOS.
