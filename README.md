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
Run `vps --help`, `vps disk --help`, or `vps audit --help` for command options.

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

Run the audit on the Linux VPS you want to check. `vps audit` runs OpenSCAP
with the installed CIS Level 1 Server profile for that distribution when
available. It needs the `oscap` executable and a local SCAP data stream that
matches the VPS distribution and release.

On Ubuntu, install the scanner with `sudo apt install openscap-scanner`.
Install the matching SCAP Security Guide content or get the data stream
from a ComplianceAsCode release. For Ubuntu 24.04, use `ssg-ubuntu2404-ds.xml`.
To use a local copy as shown below, save that file in the repository root. [Ubuntu scanner package](https://packages.ubuntu.com/noble/openscap-scanner) · [ComplianceAsCode releases](https://github.com/ComplianceAsCode/content/releases)

```sh
uv run vps audit
uv run vps audit --json
uv run vps audit --all
```

Pass `--datastream` if the file is outside a system SCAP content directory.

```sh
uv run vps audit --datastream ./ssg-ubuntu2404-ds.xml
```

The terminal report shows the evaluated profile, coverage, and up to six
findings that need attention. Failed checks appear first, with the highest
severity at the top. Evidence shows what OpenSCAP reported. Remediation comes
from the benchmark. Hints give a next step when a check needs manual review
or the benchmark lacks remediation text. Use `--all` to see every selected
check. Use `--profile ID` to choose another profile from `oscap info DATASTREAM`.

Run with root privileges for checks that need access to protected files
and live system settings. After `uv sync --locked`, use `sudo .venv/bin/vps audit`
from a trusted checkout. Pass `--datastream` as needed. The audit reads local
settings and reports results. It leaves system settings untouched. Rules that
need script-based check engines appear as unverified. [OpenSCAP user manual](https://github.com/OpenSCAP/openscap/blob/main/docs/manual/manual.adoc)

### Quick check

Run `uv run vps audit --fast` for the five local checks. The quick check
works without an OpenSCAP installation.

| Check | Evidence |
| --- | --- |
| SSH root and password login | Global OpenSSH settings from `sshd -T`. |
| Network listeners | Local TCP and UDP sockets bound beyond loopback. |
| Inbound firewall | Live nftables default-drop input policy for IPv4 and IPv6. |
| Automatic updates | Effective APT unattended-upgrade schedule, where available. |

The quick check uses your current permissions. Check the provider firewall
and SSH `Match` overrides separately. Review installed security updates and
recent update runs on the host. Keep a working login or provider console open
while you validate SSH or firewall changes. [OpenSSH server guide](https://ubuntu.com/server/docs/how-to/security/openssh-server/) · [nftables policies](https://netfilter.org/projects/nftables/manpage.html) · [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/)

### Audit JSON and exit codes

`vps audit --json` writes a versioned OpenSCAP report to stdout. It includes
the scanner, profile, and content versions, whether the scan ran with root
privileges, and all selected checks. The `summary` counts the original XCCDF
statuses. Each finding includes an ID, title, references, status, severity,
evidence, and optional remediation and hint text.

Use `vps audit --fast --json` for the five-check report schema. It contains
the quick verdict, status counts, findings, and scope. Both modes write
diagnostics to stderr.

| Exit code | Meaning |
| --- | --- |
| `0` | The assessed profile or quick checks passed. |
| `1` | The audit found a failure or a quick check needs review. |
| `2` | The command could not complete. Check the arguments, platform, and OpenSCAP setup. |
| `3` | The audit has incomplete coverage and reported no failures. |

## Development

See [AGENTS.md](AGENTS.md) for module boundaries and local checks. GitHub Actions
runs lint, format, tests, and packaging checks on Linux and macOS.
