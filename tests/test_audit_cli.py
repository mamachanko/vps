import json

import pytest
from rich.text import Text
from typer.testing import CliRunner

from vps import cli
from vps.audit import AuditReport, Finding, Status
from vps.openscap import OpenScapError, OpenScapFinding, OpenScapReport


def use_audit_report(
    monkeypatch: pytest.MonkeyPatch, findings: tuple[Finding, ...], host: str = "edge"
) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        cli, "collect_audit", lambda: AuditReport(host, "Ubuntu", findings)
    )


def test_audit_shows_verdict_evidence_and_next_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_audit_report(
        monkeypatch,
        (
            Finding(
                "ssh_root_login",
                "Direct root login",
                Status.ACTION,
                "Global PermitRootLogin is yes.",
                "Test key-based login from a second session.",
            ),
            Finding(
                "firewall_input_policy",
                "Inbound firewall",
                Status.UNKNOWN,
                "Permission denied reading nftables.",
                "Check the provider firewall.",
            ),
            Finding(
                "automatic_updates", "Automatic updates", Status.PASS, "Scheduled."
            ),
        ),
    )

    result = CliRunner().invoke(cli.app, ["audit", "--fast"], terminal_width=80)
    text = Text.from_ansi(result.stdout).plain

    assert result.exit_code == 1
    assert result.stderr == ""
    assert "VPS quick audit" in text and "Action needed" in text
    assert "edge" in text and "Ubuntu" in text
    assert "1 to fix" in text and "1 unverified" in text and "1 passed" in text
    assert text.index("Direct root login") < text.index("Inbound firewall")
    assert "Global PermitRootLogin is yes." in text
    assert "Next" in text and "Test key-based login from a second session." in text
    assert "Local Linux baseline" in text


@pytest.mark.parametrize(
    ("status", "verdict", "exit_code"),
    [
        (Status.PASS, "baseline_passed", 0),
        (Status.ACTION, "action_needed", 1),
        (Status.REVIEW, "review_needed", 1),
        (Status.UNKNOWN, "incomplete", 3),
    ],
)
def test_audit_json_and_exit_status(
    monkeypatch: pytest.MonkeyPatch, status: Status, verdict: str, exit_code: int
) -> None:
    use_audit_report(
        monkeypatch,
        (Finding("ssh_root_login", "Direct root login", status, "Observed value."),),
    )

    result = CliRunner().invoke(cli.app, ["audit", "--fast", "--json"])

    assert result.exit_code == exit_code
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["host"] == "edge" and report["system"] == "Ubuntu"
    assert report["verdict"] == verdict
    assert report["summary"] == {kind.value: int(kind is status) for kind in Status}
    assert report["findings"] == [
        {
            "id": "ssh_root_login",
            "title": "Direct root login",
            "status": status,
            "evidence": "Observed value.",
            "hint": None,
        }
    ]
    assert "Local Linux baseline" in report["scope"]


def test_audit_ascii_escapes_host_data(monkeypatch: pytest.MonkeyPatch) -> None:
    use_audit_report(
        monkeypatch,
        (Finding("automatic_updates", "Updates", Status.PASS, "[yes]"),),
        "café\x1b[2J",
    )

    result = CliRunner(charset="ascii").invoke(cli.app, ["audit", "--fast"])

    assert result.exit_code == 0
    assert r"caf\xe9\x1b[2J" in result.stdout
    assert "\x1b[2J" not in result.stdout
    assert "[yes]" in result.stdout


def test_audit_requires_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(cli, "collect_audit", lambda: pytest.fail("ran Linux probes"))

    result = CliRunner().invoke(cli.app, ["audit", "--json"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Security audit requires Linux" in result.stderr


@pytest.fixture
def openscap_report(monkeypatch: pytest.MonkeyPatch) -> OpenScapReport:
    report = OpenScapReport(
        host="edge",
        system="Ubuntu 24.04 LTS",
        engine_version="1.3.9",
        benchmark_version="0.1.82",
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        profile_title="CIS Ubuntu Linux 24.04 LTS Benchmark for Level 1 - Server",
        profile_version="1.0.0",
        privileged=False,
        findings=(
            OpenScapFinding(
                "aide",
                "Install AIDE",
                ("CIS 6.3.1",),
                "fail",
                "medium",
                "AIDE absent.",
                None,
            ),
            OpenScapFinding(
                "ssh",
                "Disable empty passwords",
                ("CIS 5.1.10",),
                "fail",
                "high",
                "Empty passwords are enabled.",
                "Set these values.\n\nPermitEmptyPasswords no\nPermitRootLogin no",
            ),
            OpenScapFinding(
                "root_login",
                "Disable SSH root login",
                (),
                "pass",
                "low",
                "Passed.",
                None,
            ),
            OpenScapFinding(
                "access",
                "Limit SSH access",
                (),
                "error",
                "unknown",
                "Permission denied.",
                None,
            ),
        ),
    )
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli, "assess", lambda **options: report)
    monkeypatch.setattr(cli, "collect_audit", lambda: pytest.fail("ran quick checks"))
    return report


@pytest.mark.parametrize("width", [42, 80])
def test_audit_defaults_to_the_findings_brief(
    openscap_report: OpenScapReport, width: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", str(width))
    result = CliRunner().invoke(cli.app, ["audit"])
    plain = Text.from_ansi(result.stdout).plain

    assert result.exit_code == 1 and result.stderr == ""
    assert "ACTION NEEDED" in plain and "CIS Level 1 Server v1.0.0" in " ".join(
        plain.split()
    )
    assert "2 failed" in plain and "1 unverified" in plain and "1 passed" in plain
    assert plain.index("Disable empty passwords") < plain.index("Install AIDE")
    assert "HIGH" in plain and "MEDIUM" in plain and "UNRATED" in plain
    assert "Evidence" in plain and "Remediation" in plain and "Hint" in plain
    assert "Permission denied." in plain
    assert "PermitEmptyPasswords no\nPermitRootLogin no" in "\n".join(
        line.strip() for line in plain.splitlines()
    )
    assert "Disable SSH root login" not in plain
    assert all(len(line) <= width for line in plain.splitlines())


def test_audit_all_shows_passed_rules(openscap_report: OpenScapReport) -> None:
    result = CliRunner().invoke(cli.app, ["audit", "--all"], terminal_width=80)

    assert result.exit_code == 1
    assert "Disable SSH root login" in result.stdout


def test_audit_full_json_has_benchmark_identity_and_all_statuses(
    openscap_report: OpenScapReport,
) -> None:
    result = CliRunner().invoke(cli.app, ["audit", "--json"])

    assert result.exit_code == 1 and result.stderr == ""
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1 and report["engine"] == "openscap"
    assert report["profile"] == {
        "id": openscap_report.profile_id,
        "title": openscap_report.profile_title,
        "version": "1.0.0",
    }
    assert (
        report["benchmark_version"] == "0.1.82" and report["engine_version"] == "1.3.9"
    )
    assert report["summary"] == {"fail": 2, "error": 1, "pass": 1}
    assert [f["id"] for f in report["findings"]] == [
        "ssh",
        "aide",
        "access",
        "root_login",
    ]
    assert report["findings"][0]["remediation"].endswith(
        "PermitEmptyPasswords no\nPermitRootLogin no"
    )
    assert report["findings"][2]["hint"].startswith(
        "Run the audit with root privileges"
    )


def test_audit_dependency_error_only_writes_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")

    def missing_oscap(**options: object) -> OpenScapReport:
        raise OpenScapError("Install openscap-scanner.\x1b[2J")

    monkeypatch.setattr(cli, "assess", missing_oscap)
    result = CliRunner().invoke(cli.app, ["audit", "--json"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert r"Install openscap-scanner.\x1b[2J" in result.stderr


def test_fast_rejects_openscap_options(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli, "collect_audit", lambda: pytest.fail("ran quick checks"))
    result = CliRunner().invoke(cli.app, ["audit", "--fast", "--profile", "cis"])

    assert result.exit_code == 2
    assert "OpenSCAP mode" in result.stderr
