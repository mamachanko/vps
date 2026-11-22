import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from vps.audit import AuditReport, Finding, Status, Verdict, collect_audit


def ssh_settings(
    root: str = "no",
    password: str = "no",
    interactive: str = "no",
    methods: str = "any",
) -> str:
    return (
        f"permitrootlogin {root}\npasswordauthentication {password}\n"
        f"kbdinteractiveauthentication {interactive}\nauthenticationmethods {methods}\n"
    )


def ruleset(
    *policies: tuple[str, str],
    dormant: bool = False,
    family_mismatch: bool = False,
) -> str:
    entries: list[dict[str, object]] = []
    for index, (family, policy) in enumerate(policies):
        table = f"filter{index}"
        entries.append(
            {
                "table": {
                    "family": family,
                    "name": table,
                    "flags": ["dormant"] if dormant else [],
                }
            }
        )
        entries.append(
            {
                "chain": {
                    "family": "ip6" if family_mismatch else family,
                    "table": table,
                    "name": "input",
                    "type": "filter",
                    "hook": "input",
                    "prio": 0,
                    "policy": policy,
                }
            }
        )
    return json.dumps({"nftables": entries})


@dataclass
class Host:
    outputs: dict[str, str | Exception | subprocess.CompletedProcess[str]] = field(
        default_factory=lambda: {
            "sshd": ssh_settings(),
            "ss": "tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n",
            "nft": ruleset(("inet", "drop")),
            "apt-config": "UPDATE='1'\nUNATTENDED='1'\n",
        }
    )
    missing: set[str] = field(default_factory=set)
    calls: list[list[str]] = field(default_factory=list)


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> Host:
    stub = Host()

    def which(name: str, *, path: str) -> str | None:
        assert path == "/usr/sbin:/usr/bin:/sbin:/bin"
        return None if name in stub.missing else f"/usr/sbin/{name}"

    def run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 3
        assert kwargs["env"] == {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
        }
        assert not kwargs.get("shell")
        stub.calls.append(arguments)
        value = stub.outputs[Path(arguments[0]).name]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, subprocess.CompletedProcess):
            return value
        return subprocess.CompletedProcess(arguments, 0, value, "")

    monkeypatch.setattr("vps.audit.shutil.which", which)
    monkeypatch.setattr("vps.audit.subprocess.run", run)
    monkeypatch.setattr("vps.audit.platform.node", lambda: "example-vps")
    monkeypatch.setattr("vps.audit.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "vps.audit.platform.freedesktop_os_release",
        lambda: {"PRETTY_NAME": "Debian GNU/Linux"},
    )
    return stub


def findings() -> dict[str, Finding]:
    return {finding.id: finding for finding in collect_audit().findings}


def test_known_good_baseline_and_fixed_read_only_commands(host: Host) -> None:
    report = collect_audit()

    assert report.host == "example-vps"
    assert report.system == "Debian GNU/Linux"
    assert report.verdict == Verdict.BASELINE_PASSED
    assert [finding.id for finding in report.findings] == [
        "ssh_root_login",
        "ssh_password_auth",
        "network_listeners",
        "firewall_input_policy",
        "automatic_updates",
    ]
    assert all(finding.status == Status.PASS for finding in report.findings)
    assert host.calls == [
        ["/usr/sbin/sshd", "-T"],
        ["/usr/sbin/ss", "-H", "-lntu"],
        ["/usr/sbin/nft", "--json", "--terse", "list", "ruleset"],
        [
            "/usr/sbin/apt-config",
            "shell",
            "PERIODIC",
            "APT::Periodic::Enable",
            "UPDATE",
            "APT::Periodic::Update-Package-Lists",
            "UNATTENDED",
            "APT::Periodic::Unattended-Upgrade",
        ],
    ]


@pytest.mark.parametrize(
    ("statuses", "verdict"),
    [
        ([Status.PASS], Verdict.BASELINE_PASSED),
        ([Status.PASS, Status.UNKNOWN], Verdict.INCOMPLETE),
        ([Status.UNKNOWN, Status.REVIEW], Verdict.REVIEW_NEEDED),
        ([Status.REVIEW, Status.UNKNOWN, Status.ACTION], Verdict.ACTION_NEEDED),
    ],
)
def test_verdict_precedence(statuses: list[Status], verdict: Verdict) -> None:
    report = AuditReport(
        "host",
        "Linux",
        tuple(
            Finding(str(index), "Check", status, "Evidence")
            for index, status in enumerate(statuses)
        ),
    )

    assert report.verdict == verdict


def test_findings_are_sorted_by_status_with_stable_baseline_order(host: Host) -> None:
    host.outputs["sshd"] = ssh_settings("yes", "yes", "yes", "publickey,password")
    host.outputs["ss"] = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    host.outputs["nft"] = PermissionError("secret diagnostic")
    host.outputs["apt-config"] = ""

    report = collect_audit()

    assert [(finding.id, finding.status) for finding in report.findings] == [
        ("ssh_root_login", Status.ACTION),
        ("ssh_password_auth", Status.REVIEW),
        ("network_listeners", Status.REVIEW),
        ("automatic_updates", Status.REVIEW),
        ("firewall_input_policy", Status.UNKNOWN),
    ]
    assert report.verdict == Verdict.ACTION_NEEDED


@pytest.mark.parametrize(
    ("value", "status"),
    [
        ("no", Status.PASS),
        ("yes", Status.ACTION),
        ("prohibit-password", Status.REVIEW),
        ("without-password", Status.REVIEW),
        ("forced-commands-only", Status.REVIEW),
        ("invalid", Status.UNKNOWN),
    ],
)
def test_root_login_modes_remain_independent(
    host: Host, value: str, status: Status
) -> None:
    host.outputs["sshd"] = ssh_settings(root=value)

    result = findings()

    assert result["ssh_root_login"].status == status
    assert result["ssh_password_auth"].status == Status.PASS
    assert "Global on-disk settings" in result["ssh_root_login"].evidence
    if status == Status.UNKNOWN:
        assert "sshd -T" in result["ssh_root_login"].hint
    elif status != Status.PASS:
        assert "second session" in result["ssh_root_login"].hint
        assert "sshd -t" in result["ssh_root_login"].hint


@pytest.mark.parametrize(
    ("password", "interactive", "methods", "status"),
    [
        ("no", "no", "", Status.PASS),
        ("yes", "no", "any", Status.ACTION),
        ("yes", "no", "password", Status.ACTION),
        ("yes", "no", "publickey password", Status.ACTION),
        ("yes", "yes", "any", Status.ACTION),
        ("no", "yes", "any", Status.REVIEW),
        ("yes", "yes", "publickey,keyboard-interactive:pam", Status.REVIEW),
        ("yes", "no", "publickey,password", Status.REVIEW),
        ("yes", "no", "publickey", Status.REVIEW),
        (
            "yes",
            "no",
            "publickey,password publickey,keyboard-interactive",
            Status.REVIEW,
        ),
        ("yes", "no", "publickey,invalid", Status.UNKNOWN),
        ("yes", "no", "any publickey", Status.UNKNOWN),
        ("yes", "no", "", Status.UNKNOWN),
        ("yes", "invalid", "any", Status.UNKNOWN),
        ("invalid", "no", "any", Status.UNKNOWN),
    ],
)
def test_password_and_keyboard_interactive_interactions(
    host: Host,
    password: str,
    interactive: str,
    methods: str,
    status: Status,
) -> None:
    host.outputs["sshd"] = ssh_settings(
        password=password, interactive=interactive, methods=methods
    )

    result = findings()["ssh_password_auth"]

    assert result.status == status
    if status == Status.UNKNOWN:
        assert "sshd -T" in result.hint
    elif status != Status.PASS:
        assert "MFA" in result.hint
        assert "second session" in result.hint
        assert "keep the existing session open" in result.hint
        assert "sshd -t" in result.hint


@pytest.mark.parametrize("output", ["", "permitrootlogin no\npermitrootlogin yes\n"])
def test_missing_or_duplicate_ssh_values_are_unknown(host: Host, output: str) -> None:
    host.outputs["sshd"] = output

    result = findings()

    assert result["ssh_root_login"].status == Status.UNKNOWN
    assert result["ssh_password_auth"].status == Status.UNKNOWN


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1:22",
        "127.0.0.53%lo:53",
        "127.2.3.4:53",
        "[::1]:22",
        "[::ffff:127.0.0.1]:22",
        "[::ffff:7f00:1]:22",
    ],
)
def test_loopback_listener_forms_pass(host: Host, address: str) -> None:
    host.outputs["ss"] = f"tcp LISTEN 0 128 {address} *:*\n"

    assert findings()["network_listeners"].status == Status.PASS


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0:22",
        "*:53",
        "[::]:22",
        "[2001:db8::1]:443",
        "10.0.0.1:8080",
        "10.0.0.1%eth0:68",
        "[fe80::1%eth0]:53",
    ],
)
def test_nonloopback_listener_forms_require_review(host: Host, address: str) -> None:
    host.outputs["ss"] = f"udp UNCONN 0 0 {address} *:*\n"

    result = findings()["network_listeners"]

    assert result.status == Status.REVIEW
    assert "1 non-loopback TCP/UDP bindings" in result.evidence
    assert "External reachability not checked" in result.evidence
    if "%" in address:
        assert address in result.evidence
    assert "provider firewall" in result.hint


def test_listener_evidence_is_bounded_with_total_count(host: Host) -> None:
    host.outputs["ss"] = "".join(
        f"tcp LISTEN 0 128 0.0.0.0:{1000 + index} 0.0.0.0:*\n" for index in range(20)
    )

    result = findings()["network_listeners"]

    assert "20 non-loopback" in result.evidence
    assert result.evidence.count("tcp 0.0.0.0:") == 5
    assert "20 bindings inspected" in result.evidence


@pytest.mark.parametrize(
    "output",
    [
        "garbage\n",
        "tcp LISTEN 0 128 malformed *:*\n",
        "tcp LISTEN 0 128 127.0.0.1:70000 *:*\n",
        "tcp LISTEN 0 128 hostname:22 *:*\n",
        "tcp LISTEN 0 128 127.0.0.1:22 broken\n",
        "tcp LISTEN 0 128 127.0.0.1:22 *:*\nmalformed\n",
    ],
)
def test_malformed_socket_inventory_does_not_pass(host: Host, output: str) -> None:
    host.outputs["ss"] = output

    assert findings()["network_listeners"].status == Status.UNKNOWN


def test_empty_socket_inventory_passes(host: Host) -> None:
    host.outputs["ss"] = ""

    result = findings()["network_listeners"]

    assert result.status == Status.PASS
    assert "0 bindings inspected" in result.evidence


@pytest.mark.parametrize(
    ("policies", "status"),
    [
        ((("inet", "drop"),), Status.PASS),
        ((("ip", "drop"), ("ip6", "drop")), Status.PASS),
        ((("ip", "drop"),), Status.REVIEW),
        ((("ip6", "drop"),), Status.REVIEW),
        ((("inet", "accept"),), Status.REVIEW),
        ((("inet", "drop"), ("ip", "accept")), Status.PASS),
        ((), Status.REVIEW),
    ],
)
def test_live_firewall_default_policy_coverage(
    host: Host,
    policies: tuple[tuple[str, str], ...],
    status: Status,
) -> None:
    host.outputs["nft"] = ruleset(*policies)

    result = findings()["firewall_input_policy"]

    assert result.status == status
    assert "Live nftables input default policies" in result.evidence
    assert "explicit allow rules" in result.hint
    assert "provider firewall" in result.hint


def test_dormant_tables_do_not_establish_live_firewall_coverage(host: Host) -> None:
    host.outputs["nft"] = ruleset(("inet", "drop"), dormant=True)

    result = findings()["firewall_input_policy"]

    assert result.status == Status.REVIEW
    assert "Default-drop coverage: none" in result.evidence
    assert "dormant" in result.evidence


def test_chain_family_must_match_its_table(host: Host) -> None:
    host.outputs["nft"] = ruleset(("inet", "drop"), family_mismatch=True)

    assert findings()["firewall_input_policy"].status == Status.UNKNOWN


def test_regular_chain_named_input_does_not_establish_default_policy(
    host: Host,
) -> None:
    host.outputs["nft"] = json.dumps(
        {
            "nftables": [
                {"table": {"family": "inet", "name": "filter"}},
                {"chain": {"family": "inet", "table": "filter", "name": "input"}},
            ]
        }
    )

    assert findings()["firewall_input_policy"].status == Status.REVIEW


@pytest.mark.parametrize(
    "output",
    [
        "not JSON",
        "[]",
        "{}",
        '{"nftables": {}}',
        '{"nftables": [null]}',
        '{"nftables": [{"table": null}]}',
        '{"nftables": [{"chain": {}}]}',
        ruleset(("inet", "invalid")),
    ],
)
def test_malformed_or_unsupported_nft_output_is_unknown(
    host: Host, output: str
) -> None:
    host.outputs["nft"] = output

    assert findings()["firewall_input_policy"].status == Status.UNKNOWN


def test_firewall_does_not_copy_explicit_rule_contents(host: Host) -> None:
    data = json.loads(ruleset(("inet", "drop")))
    data["nftables"].append({"rule": {"comment": "sensitive-rule-comment"}})
    host.outputs["nft"] = json.dumps(data)

    result = findings()["firewall_input_policy"]

    assert result.status == Status.PASS
    assert "sensitive-rule-comment" not in result.evidence


@pytest.mark.parametrize(
    ("settings", "status"),
    [
        ("UPDATE='1'\nUNATTENDED='1'\n", Status.PASS),
        ("PERIODIC='1'\nUPDATE='always'\nUNATTENDED='7'\n", Status.PASS),
        ("UPDATE='12h';\nUNATTENDED='2d';\n", Status.PASS),
        ("PERIODIC='0'\nUPDATE='1'\nUNATTENDED='1'\n", Status.REVIEW),
        ("UPDATE='0'\nUNATTENDED='1'\n", Status.REVIEW),
        ("UPDATE='1'\nUNATTENDED='0'\n", Status.REVIEW),
        ("UPDATE='1'\n", Status.REVIEW),
        ("", Status.REVIEW),
        ("UPDATE='0s'\nUNATTENDED='0d'\n", Status.REVIEW),
        ("UPDATE='invalid'\nUNATTENDED='1'\n", Status.UNKNOWN),
        ("PERIODIC='false'\nUPDATE='1'\nUNATTENDED='1'\n", Status.UNKNOWN),
        ("UPDATE='1'\nUNATTENDED='-1'\n", Status.UNKNOWN),
        ("UPDATE='1'\nUNATTENDED='1'; execute-secret\n", Status.UNKNOWN),
        ("UPDATE='1'\nUPDATE='0'\nUNATTENDED='1'\n", Status.UNKNOWN),
        ("unexpected='1'\n", Status.UNKNOWN),
    ],
)
def test_apt_schedule_configuration(host: Host, settings: str, status: Status) -> None:
    host.outputs["apt-config"] = settings

    result = findings()["automatic_updates"]

    assert result.status == status
    assert "recent" in result.hint
    assert "another distribution" in result.hint
    if status != Status.UNKNOWN:
        assert "Review recent runs and installed patches" in result.evidence


def test_configured_updates_need_unattended_upgrade_executable(host: Host) -> None:
    host.missing.add("unattended-upgrade")

    result = findings()["automatic_updates"]

    assert result.status == Status.REVIEW
    assert "executable not found" in result.evidence


@pytest.mark.parametrize(
    ("tool", "ids"),
    [
        ("sshd", ("ssh_root_login", "ssh_password_auth")),
        ("ss", ("network_listeners",)),
        ("nft", ("firewall_input_policy",)),
        ("apt-config", ("automatic_updates",)),
    ],
)
def test_missing_tools_are_unknown_without_hiding_other_checks(
    host: Host,
    tool: str,
    ids: tuple[str, ...],
) -> None:
    host.missing.add(tool)

    result = findings()

    for finding_id, finding in result.items():
        assert finding.status == (Status.UNKNOWN if finding_id in ids else Status.PASS)
        if finding_id in ids:
            assert "standard system directories" in finding.evidence


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (PermissionError("private error"), "Permission denied"),
        (FileNotFoundError("private error"), "no longer available"),
        (OSError("private error"), "could not be executed"),
        (subprocess.TimeoutExpired("private-command", 3, output="secret"), "timed out"),
        (
            subprocess.CompletedProcess(
                [], 1, "secret output", "Operation not permitted secret"
            ),
            "Permission denied",
        ),
        (
            subprocess.CompletedProcess(
                [], 2, "secret output", "secret unexpected error"
            ),
            "exit status 2",
        ),
    ],
)
def test_tool_failures_are_sanitized_and_unknown(
    host: Host,
    failure: Exception | subprocess.CompletedProcess[str],
    expected: str,
) -> None:
    host.outputs["nft"] = failure

    result = findings()["firewall_input_policy"]

    assert result.status == Status.UNKNOWN
    assert expected in result.evidence
    assert "secret" not in result.evidence
    assert "private" not in result.evidence


def test_excessive_tool_output_is_unknown_without_echoing_it(host: Host) -> None:
    host.outputs["ss"] = "x" * (1024 * 1024 + 1)

    result = findings()["network_listeners"]

    assert result.status == Status.UNKNOWN
    assert len(result.evidence) < 100


def test_host_metadata_falls_back_and_is_bounded(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> dict[str, str]:
        raise OSError("unreadable os-release")

    monkeypatch.setattr("vps.audit.platform.freedesktop_os_release", unavailable)
    monkeypatch.setattr("vps.audit.platform.node", lambda: "h" * 1000)

    report = collect_audit()

    assert report.system == "Linux"
    assert len(report.host) == 255


def test_host_metadata_empty_values_have_safe_fallbacks(
    host: Host,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vps.audit.platform.freedesktop_os_release", lambda: {})
    monkeypatch.setattr("vps.audit.platform.node", lambda: "")

    report = collect_audit()

    assert report.system == "Linux"
    assert report.host == "unknown"


def test_arbitrary_path_is_not_used_for_host_tools(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", os.devnull)

    assert collect_audit().verdict == Verdict.BASELINE_PASSED
