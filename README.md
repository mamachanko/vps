# vps

See what's filling a filesystem and which hardening checks need attention.
`vps` is a read-only CLI you can run directly on a server over SSH.

| Command | What it shows | Where it runs |
| --- | --- | --- |
| `vps disk` | Filesystem capacity and, with `--top`, the largest entries in a directory | Linux and macOS |
| `vps audit` | An OpenSCAP assessment against a CIS Level 1 Server profile by default | Linux with OpenSCAP and matching benchmark content |
| `vps audit --fast` | Five local checks for SSH, network listeners, firewall policy, and updates | Linux |

## Quick start

Install uv and use Python 3.11 or newer. Run these commands on the machine you
want to inspect. [Install uv](https://docs.astral.sh/uv/getting-started/installation/)

```sh
git clone https://github.com/mamachanko/vps.git
cd vps
uv sync --locked
uv run vps disk
```

Keep using `uv run vps` from the checkout. To use `vps` from any directory,
run `uv tool install .` from the checkout. Use `uv run vps --help` to list
commands.

## Disk usage

```sh
uv run vps disk /var
uv run vps disk /var --top 10
uv run vps disk /var --top 10 --json
```

`disk [PATH]` shows capacity for the filesystem that contains the path.
The default is `/`. Pass a directory with `--top N` to rank its largest
immediate entries, including their descendants. A spinner on an interactive
terminal shows that the scan is still running.

The ranking uses allocated space, so a sparse file counts for the blocks it
occupies. The scan includes hidden entries, skips other filesystems, and
counts each hard link target once. The first top-level entry by name gets
credit for the allocation. If you pass a symlink as the initial path, the
scan follows it to its target. Inside the tree it counts each symlink itself.

The capacity percentage compares used bytes with the sum of used and
user-available bytes, as in `df`. The report shows reserved space when the
filesystem exposes it. If part of the tree is unreadable, the report still
includes the entries it could inspect and exits with code `3`.

## Security audit

If `oscap` is on your `PATH` and the matching SCAP data stream is installed
in a system SCAP directory, run `uv run vps audit` on the Linux server. To run
without OpenSCAP, use the [quick check](#quick-check).

### Set up OpenSCAP on Ubuntu 24.04

Install the scanner and download benchmark content for Ubuntu 24.04.
The example uses ComplianceAsCode content version `0.1.82`, which includes
the CIS Level 1 Server profile. [Ubuntu scanner package](https://packages.ubuntu.com/noble/openscap-scanner) · [ComplianceAsCode release](https://github.com/ComplianceAsCode/content/releases/tag/v0.1.82)

```sh
sudo apt update
sudo apt install openscap-scanner curl unzip

scap_dir=$(mktemp -d)
curl -fL -o "$scap_dir/content.zip" \
  https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip
unzip -j "$scap_dir/content.zip" '*/ssg-ubuntu2404-ds.xml' -d "$scap_dir"

uv run vps audit --datastream "$scap_dir/ssg-ubuntu2404-ds.xml"
```

Use a data stream built for your distribution and release. If you supply one
with a different profile, list its profiles with `oscap info DATASTREAM`
and pass `--profile ID`. Use `--oscap PATH` if the scanner is outside your
`PATH`.

Run with root privileges to cover protected files and live settings. After
`uv sync --locked`, run the installed entry point from a trusted checkout.
The command below uses the data stream downloaded above.

```sh
sudo .venv/bin/vps audit --datastream "$scap_dir/ssg-ubuntu2404-ds.xml"
```

### Read the report

This excerpt comes from an Ubuntu 24.04 container scan.

```text
ACTION NEEDED  OpenSCAP / Ubuntu 24.04.5 LTS / CIS Level 1 Server v1.0.0
8a4fb0ac9419 / OpenSCAP 1.3.9 / Content 0.1.82 / Root
6 failed   2 unverified   130 passed   270 not applicable

FAIL         Install pam_pwquality Package                                MEDIUM
             CIS 5.3.1.3
             Evidence     OpenSCAP supplied no rule-specific evidence.
             Remediation  The libpam-pwquality package can be installed with the
                          following command:

                          $ apt-get install libpam-pwquality
```

The terminal report shows up to six findings, with failed rules first and
the highest severity first within each group. **Evidence** comes from
OpenSCAP. **Remediation** comes from the benchmark. A **Hint** suggests a
follow-up if a rule needs manual review or lacks remediation guidance.

Add `--all` to see every selected rule or `--json` to get the full report as JSON.
Rules that need a script-based check engine appear as unverified. Review
coverage alongside the verdict. [OpenSCAP result definitions](https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html#_evaluating_xccdf)

### Quick check

```sh
uv run vps audit --fast
```

The quick check reads global OpenSSH settings for root and password login,
TCP and UDP listeners bound beyond loopback, live nftables input policy,
and the effective APT unattended-upgrade schedule where available. It uses
your current permissions.

Review provider firewall rules, SSH `Match` overrides, and recent security
updates separately. Keep a working SSH session or provider console open
when validating SSH or firewall changes. [Ubuntu OpenSSH guide](https://ubuntu.com/server/docs/how-to/security/openssh-server/) · [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/)

## JSON and exit codes

Both commands accept `--json`. They send one versioned JSON report to stdout
and diagnostics to stderr. Each mode has its own schema with `schema_version`
set to `1`.

| Mode | Report fields |
| --- | --- |
| `disk --json` | Absolute `path`, `filesystem` capacity, and optional `scan` |
| `audit --json` | Host and profile, scanner and content versions, privileges, verdict, counts by XCCDF status, and all selected rule results |
| `audit --fast --json` | Host, verdict, counts by quick-check status, findings, and scope |

Disk sizes are integer bytes. `filesystem` contains `total_bytes`,
`used_bytes`, `available_bytes`, `reserved_bytes`, and `used_percent`.
Without `--top`, `scan` is `null`. A directory scan includes ranked
`entries` with `name` and `allocated_bytes`, `skipped_other_devices`,
`issue_count`, and up to five `issues` with a `path` and `message`.

OpenSCAP findings include the rule ID, title, references, status, severity,
evidence, and optional remediation and hint text.

| Code | `disk` | `audit` and `audit --fast` |
| --- | --- | --- |
| `0` | Complete report | Profile or quick checks passed |
| `1` | Inspection failed | A check failed or needs review |
| `2` | Invalid arguments | Invalid arguments, unsupported platform, or OpenSCAP setup or execution error |
| `3` | Partial scan | Incomplete coverage with no failed checks |

## Development

```sh
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest
uv build
```

See [AGENTS.md](AGENTS.md) for module boundaries and the
[verification guide](.agents/skills/verify/SKILL.md) for checks through the
installed CLI. [GitHub Actions](.github/workflows/ci.yml) runs the checks on
Linux and macOS.

[MIT license](LICENSE)
