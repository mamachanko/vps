#!/usr/bin/env python3
import argparse
import errno
import json
import os
import platform
import pty
import select
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import BinaryIO

REPO = Path(__file__).resolve().parents[4]
VPS = Path(sys.executable).with_name("vps")
TIMEOUT = 20
STATUS = b"Scanning disk usage..."


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def read_pty(master: int, transcript: BinaryIO, deadline: float) -> None:
    while (remaining := deadline - time.monotonic()) > 0 and select.select(
        [master], [], [], remaining
    )[0]:
        try:
            chunk = os.read(master, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return
            raise
        if not chunk:
            return
        transcript.write(chunk)
    raise TimeoutError(f"Terminal did not close within {TIMEOUT} seconds.")


class Driver:
    def __init__(self, evidence: Path, fixture: Path) -> None:
        self.evidence = evidence
        self.fixture = fixture

    def run(
        self,
        label: str,
        *args: str | Path,
        terminal: bool = False,
        code: int | tuple[int, ...] = 0,
    ) -> tuple[bytes, bytes]:
        argv = [str(VPS), *map(str, args)]
        env = os.environ.copy()
        for setting in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
            env.pop(setting, None)
        env.update(TERM="xterm-256color" if terminal else "dumb", COLUMNS="80")
        stdout = self.evidence / f"{label}.stdout"
        stderr = self.evidence / f"{label}.stderr"
        record: dict[str, object] = {
            "argv": argv,
            "cwd": str(REPO),
            "stderr_is_pty": terminal,
            "exit_code": None,
        }
        try:
            with stdout.open("wb") as out, stderr.open("wb") as err:
                if terminal:
                    master, slave = pty.openpty()
                    try:
                        deadline = time.monotonic() + TIMEOUT
                        with subprocess.Popen(
                            argv,
                            cwd=REPO,
                            env=env,
                            stdin=subprocess.DEVNULL,
                            stdout=out,
                            stderr=slave,
                        ) as process:
                            os.close(slave)
                            slave = -1
                            try:
                                read_pty(master, err, deadline)
                                process.wait(
                                    timeout=max(0, deadline - time.monotonic())
                                )
                            except BaseException:
                                process.kill()
                                raise
                            finally:
                                record["exit_code"] = process.poll()
                    finally:
                        os.close(master)
                        if slave >= 0:
                            os.close(slave)
                else:
                    process = subprocess.run(
                        argv,
                        cwd=REPO,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=out,
                        stderr=err,
                        timeout=TIMEOUT,
                        check=False,
                    )
                    record["exit_code"] = process.returncode
        finally:
            (self.evidence / f"{label}.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8"
            )
        expected_codes = (code,) if isinstance(code, int) else code
        require(
            record["exit_code"] in expected_codes,
            f"{label}: expected exit {code}, got {record['exit_code']}. See {stderr}.",
        )
        return stdout.read_bytes(), stderr.read_bytes()


def doctor(driver: Driver) -> None:
    with (REPO / "pyproject.toml").open("rb") as file:
        version = tomllib.load(file)["project"]["version"]
    stdout, _ = driver.run("version", "--version")
    require(
        stdout == f"vps {version}\n".encode(),
        "Installed version differs from pyproject.toml.",
    )
    stdout, _ = driver.run("disk-help", "disk", "--help")
    require(
        b"--top" in stdout and b"--json" in stdout,
        "Disk options are missing from help.",
    )


def capacity(driver: Driver) -> None:
    stdout, stderr = driver.run("root-json", "disk", "--json")
    report = json.loads(stdout)
    stats = os.statvfs("/")
    usage = report["filesystem"]
    require(not stderr, "Capacity JSON wrote diagnostics.")
    require(
        report["schema_version"] == 1
        and report["path"] == "/"
        and report["scan"] is None,
        "Expected a capacity-only report for /.",
    )
    require(
        usage["total_bytes"] == stats.f_blocks * (stats.f_frsize or stats.f_bsize)
        and usage["used_bytes"] + usage["available_bytes"] + usage["reserved_bytes"]
        == usage["total_bytes"],
        "Reported capacity differs from filesystem accounting.",
    )

    target = driver.fixture / "sample"
    target.write_bytes(b"sample")
    stdout, stderr = driver.run("file-capacity", "disk", target)
    require(
        not stderr and os.fsencode(target) in stdout and b"available" in stdout,
        "Human capacity report is missing the path or available space.",
    )
    require(
        target.read_bytes() == b"sample", "The inspection changed the fixture file."
    )


def allocation(path: Path) -> int:
    return path.lstat().st_blocks * 512


def ranking(driver: Driver) -> None:
    root = driver.fixture / "scan"
    logs = root / "logs"
    logs.mkdir(parents=True)
    payload = logs / "data"
    payload.write_bytes(b"x" * 65536)
    (root / "mirror").hardlink_to(payload)
    hidden = root / ".hidden"
    hidden.write_bytes(b"x")
    sparse = root / "sparse"
    with sparse.open("wb") as file:
        file.truncate(16 * 1024 * 1024)
    outside = driver.fixture / "outside"
    outside.mkdir()
    (outside / "data").write_bytes(b"x" * 262144)
    link = root / "link"
    link.symlink_to(outside, target_is_directory=True)
    sizes = {
        ".hidden": allocation(hidden),
        "link": allocation(link),
        "logs": allocation(logs) + allocation(payload),
        "mirror": 0,
        "sparse": allocation(sparse),
    }
    expected = [
        {"name": name, "allocated_bytes": sizes[name]}
        for name in sorted(sizes, key=lambda name: (-sizes[name], name))
    ]

    stdout, stderr = driver.run("rank-json", "disk", root, "--top", "5", "--json")
    scan = json.loads(stdout)["scan"]
    require(
        not stderr and scan["issue_count"] == 0, "Fixture scan had unexpected errors."
    )
    require(
        scan["entries"] == expected,
        f"Expected ranked entries {expected}, got {scan['entries']}.",
    )
    stdout, stderr = driver.run("rank-human", "disk", root, "--top", "1")
    rows = [line.split() for line in stdout.splitlines() if line.strip()][-2:]
    require(
        not stderr
        and len(rows) == 2
        and rows[0] == [b"Allocated", b"Name"]
        and rows[1][-1] == expected[0]["name"].encode(),
        "Human ranking did not show just the largest fixture entry.",
    )
    require(
        {path.name for path in root.iterdir()} == sizes.keys()
        and payload.read_bytes() == b"x" * 65536
        and hidden.read_bytes() == b"x"
        and (root / "mirror").samefile(payload)
        and sparse.stat().st_size == 16 * 1024 * 1024
        and link.readlink() == outside,
        "The scan changed the fixture.",
    )


def progress(driver: Driver) -> None:
    (driver.fixture / "sample").write_bytes(b"sample")
    args = ("disk", driver.fixture, "--top", "1", "--json")
    stdout, stderr = driver.run("progress-pty", *args, terminal=True)
    start = stderr.find(STATUS)
    require(
        start >= 0 and b"\x1b[2K" in stderr[start:] and b"\x1b[?25h" in stderr[start:],
        "Expected the terminal to show the scan status, clear it, and restore the cursor.",
    )
    require(
        json.loads(stdout)["scan"]["entries"][0]["name"] == "sample",
        "Interactive status interfered with the JSON report.",
    )

    stdout, stderr = driver.run("progress-redirected", *args)
    require(
        not stderr and json.loads(stdout)["scan"]["issue_count"] == 0,
        "Redirected scan wrote status or failed to return JSON.",
    )
    stdout, stderr = driver.run(
        "progress-capacity", "disk", driver.fixture, "--json", terminal=True
    )
    require(
        not stderr and json.loads(stdout)["scan"] is None,
        "Capacity-only inspection displayed scan status.",
    )
    stdout, stderr = driver.run(
        "progress-fatal",
        "disk",
        driver.fixture / "missing",
        "--top",
        "1",
        "--json",
        terminal=True,
        code=1,
    )
    start = stderr.find(STATUS)
    require(
        not stdout
        and start >= 0
        and b"\x1b[?25h" in stderr[start:]
        and b"No such file or directory" in stderr[start:],
        "A failed scan did not restore the cursor and report the error.",
    )


def errors(driver: Driver) -> None:
    missing = driver.fixture / "missing"
    stdout, stderr = driver.run("missing", "disk", missing, "--json", code=1)
    require(
        not stdout and b"No such file or directory" in stderr,
        "Missing path diagnostic is absent.",
    )

    payload = driver.fixture / "sample"
    payload.write_bytes(b"sample")
    stdout, stderr = driver.run(
        "not-directory", "disk", payload, "--top", "1", "--json", code=2
    )
    require(
        not stdout and b"requires a directory" in stderr,
        "Directory diagnostic is absent.",
    )

    require(
        os.geteuid() != 0,
        "Run the partial scan as an unprivileged user to exercise permission denial.",
    )
    locked = driver.fixture / "locked"
    locked.mkdir()
    (locked / "data").write_bytes(b"private")
    locked.chmod(0)
    try:
        stdout, stderr = driver.run(
            "partial", "disk", driver.fixture, "--top", "10", "--json", code=3
        )
    finally:
        locked.chmod(0o700)
    scan = json.loads(stdout)["scan"]
    require(
        b"partial scan" in stderr
        and scan["issue_count"] == 1
        and scan["issues"][0]["path"] == str(locked)
        and any(entry["name"] == "sample" for entry in scan["entries"]),
        "Partial scan did not retain readable entries and name the unreadable directory.",
    )


def audit(driver: Driver) -> None:
    if platform.system() != "Linux":
        stdout, stderr = driver.run("audit-unsupported", "audit", "--json", code=2)
        require(
            not stdout and b"requires Linux" in stderr, "Expected a Linux diagnostic."
        )
        return

    exits = {
        "action_needed": 1,
        "review_needed": 1,
        "incomplete": 3,
        "baseline_passed": 0,
    }
    stdout, stderr = driver.run("audit-json", "audit", "--json", code=(0, 1, 3))
    report = json.loads(stdout)
    require(
        not stderr and report["schema_version"] == 1,
        "Expected a versioned JSON report on stdout and empty redirected stderr.",
    )
    checks = {
        "ssh_root_login",
        "ssh_password_auth",
        "network_listeners",
        "firewall_input_policy",
        "automatic_updates",
    }
    findings = report["findings"]
    require(
        len(findings) == len(checks)
        and {finding["id"] for finding in findings} == checks,
        "Expected all five baseline checks.",
    )
    statuses = ("action", "review", "unknown", "pass")
    ordered = [statuses.index(finding["status"]) for finding in findings]
    require(ordered == sorted(ordered), "Findings are out of priority order.")
    require(
        all(
            finding["evidence"] and (finding["status"] == "pass" or finding["hint"])
            for finding in findings
        ),
        "A finding lacks evidence or a next step.",
    )
    require(
        report["summary"]
        == {status: ordered.count(i) for i, status in enumerate(statuses)},
        "Summary counts differ from the findings.",
    )
    recorded = json.loads((driver.evidence / "audit-json.json").read_bytes())
    require(
        recorded["exit_code"] == exits[report["verdict"]],
        "Audit exit code differs from its verdict.",
    )

    stdout, stderr = driver.run("audit-human", "audit", terminal=True, code=(0, 1, 3))
    require(
        b"VPS security audit" in stdout
        and b"Local Linux baseline" in stdout
        and b"Checking server hardening..." in stderr
        and b"\x1b[?25h" in stderr,
        "Expected a scoped terminal report and cursor restoration after the audit.",
    )


JOURNEYS = {
    "doctor": doctor,
    "capacity": capacity,
    "ranking": ranking,
    "progress": progress,
    "errors": errors,
    "audit": audit,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Drive the installed vps CLI and save evidence."
    )
    parser.add_argument("journey", choices=JOURNEYS)
    args = parser.parse_args()
    evidence = Path(tempfile.mkdtemp(prefix="vps-evidence-"))
    print(f"Evidence: {evidence}", flush=True)
    with tempfile.TemporaryDirectory(prefix="vps-fixture-") as directory:
        record = {"journey": args.journey, "fixture": directory, "verdict": "failed"}
        try:
            require(VPS.is_file(), "Run uv sync --locked before driving vps.")
            JOURNEYS[args.journey](Driver(evidence, Path(directory)))
            record["verdict"] = "passed"
        except (
            VerificationError,
            OSError,
            ValueError,
            LookupError,
            TypeError,
            subprocess.TimeoutExpired,
        ) as error:
            record["error"] = str(error)
            print(f"FAIL {args.journey}: {error}", file=sys.stderr)
            return 1
        finally:
            (evidence / "run.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8"
            )
    print(f"PASS {args.journey}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
