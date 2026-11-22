import json

import pytest
from rich.text import Text
from typer.testing import CliRunner

from vps import cli
from vps.audit import AuditReport, Finding, Status


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

    result = CliRunner().invoke(cli.app, ["audit"], terminal_width=80)
    text = Text.from_ansi(result.stdout).plain

    assert result.exit_code == 1
    assert result.stderr == ""
    assert "VPS security audit" in text and "Action needed" in text
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

    result = CliRunner().invoke(cli.app, ["audit", "--json"])

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

    result = CliRunner(charset="ascii").invoke(cli.app, ["audit"])

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
