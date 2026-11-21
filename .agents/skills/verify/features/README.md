# vps verification map

Use the matching journey to verify a change through the installed `vps`
command. Start with [launch and doctor](../SKILL.md).

## Baseline preconditions

- Run from the vps checkout on Linux or macOS after `uv sync --locked`.
- Use a writable temporary filesystem that supports hard links and symlinks.
- Run the error journey as an unprivileged user to exercise permission denial.

## Driving conventions

Each journey starts with a fresh fixture. The driver captures stdout, stderr,
and the exit code. The scan status journey supplies a pseudo-terminal for
stderr and keeps stdout on a separate stream.

## Proof and skip reporting

Read the recorded arguments and streams alongside the exit code. Keep the
evidence directory after fixture cleanup. If a precondition fails, report the
attempted journey and the missing precondition.

## Features

- [Filesystem capacity](capacity.md) covers the default filesystem and an explicit file.
- [Directory ranking](ranking.md) covers scan limits and allocated disk space.
- [Scan status](progress.md) covers interactive stderr and redirected output.
- [Errors and partial results](errors.md) covers exit codes and recoverable scan errors.
