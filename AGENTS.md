# Working on vps

Use Python 3.11 or newer on a POSIX system. Run `uv sync --locked` from the
repository root before development.

- Keep Typer argument handling and exit codes in `src/vps/cli.py`.
- Keep filesystem inspection and accounting in `src/vps/disk.py`.
- Keep the Rich display and JSON encoder in `src/vps/disk_output.py`.
- Keep machine output stable. Update the README and command tests if the JSON
  contract changes.
- Test command behavior through Typer's CLI runner and filesystem behavior
  with temporary directories. Keep tests independent of the host's disk size.

Run these checks before handing off a change.

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest
uv build
```
