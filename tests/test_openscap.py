import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

from vps.audit import Verdict
from vps.openscap import OpenScapError, OpenScapFinding, OpenScapReport, assess

PROFILE = "xccdf_org.ssgproject.content_profile_cis_level1_server"
RULE = "xccdf_org.ssgproject.content_rule_ssh_root_login"
NAMESPACE = "http://checklists.nist.gov/xccdf/1.2"


def content(*, profiles: str | None = None, description: str | None = None) -> str:
    if profiles is None:
        profiles = (
            f'<Profile id="{PROFILE}"><title>CIS Example Level 1 Server</title>'
            "<version>1.0.0</version></Profile>"
        )
    if description is None:
        description = (
            "<description>The root account is privileged. "
            "<h:p>Set <h:code>PermitRootLogin <sub idref='root_value'/>"
            "</h:code> in the SSH configuration.</h:p>"
            "<h:p>Check the configuration before reloading SSH.</h:p></description>"
        )
    return (
        '<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2">'
        f'<component><Benchmark xmlns="{NAMESPACE}" '
        'xmlns:h="http://www.w3.org/1999/xhtml" id="example">'
        "<version>0.1.82</version>"
        f"{profiles}<Group id='ssh'><Rule id='{RULE}' severity='medium'>"
        "<title>Disable SSH Root Login</title>"
        "<reference href='https://www.cisecurity.org/benchmark/ubuntu_linux'>"
        "5.1.20</reference>"
        "<reference href='https://www.cisecurity.org/controls/'>1</reference>"
        "<reference href='https://example.org'>AC-1</reference>"
        f"{description}</Rule></Group></Benchmark></component>"
        "</data-stream-collection>"
    )


def results(
    *statuses: str,
    profile: str = PROFILE,
    identity: str = '<identity authenticated="false" privileged="false">root</identity>',
    scanner: str = (
        "<target-facts><fact name='urn:xccdf:fact:scanner:version'>"
        "1.3.9</fact></target-facts>"
    ),
    messages: str = "",
    attributes: str = "",
    rule_id: str = RULE,
) -> str:
    rows = "".join(
        f'<rule-result idref="{rule_id}" {attributes}><result>{status}</result>'
        f"{messages}</rule-result>"
        for status in statuses
    )
    return (
        f'<Benchmark xmlns="{NAMESPACE}" id="example">'
        "<TestResult id='result'>"
        f"{identity}<profile idref='{profile}'/><target>example-vps</target>"
        f"{scanner}<set-value idref='root_value'>no</set-value>"
        f"{rows}</TestResult></Benchmark>"
    )


@dataclass
class Scanner:
    datastream: Path
    result_xml: str = field(default_factory=lambda: results("pass"))
    exit: int = 0
    stderr: str = ""
    exception: Exception | None = None
    calls: list[list[str]] = field(default_factory=list)
    directories: list[Path] = field(default_factory=list)


@pytest.fixture
def scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Scanner:
    datastream = tmp_path / "ssg-ubuntu2404-ds.xml"
    datastream.write_text(content())
    stub = Scanner(datastream)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        stub.calls.append(command)
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["check"] is False
        assert not kwargs.get("shell")
        env = kwargs["env"]
        assert isinstance(env, dict)
        assert env["LC_ALL"] == "C"
        assert env["LANG"] == "C"
        assert "OSCAP_PROBE_ROOT" not in env
        assert "OSCAP_EVALUATION_TARGET" not in env
        assert "OSCAP_OVAL_COMMAND_OPTIONS" not in env
        assert "OSCAP_CONTAINER_VARS" not in env
        plugins = Path(env["OSCAP_CHECK_ENGINE_PLUGIN_DIR"])
        assert plugins.is_dir()
        assert not list(plugins.iterdir())
        result_path = Path(command[command.index("--results") + 1])
        stub.directories.append(result_path.parent)
        if stub.exception:
            raise stub.exception
        result_path.write_text(stub.result_xml)
        kwargs["stderr"].write(stub.stderr)
        return subprocess.CompletedProcess(command, stub.exit)

    monkeypatch.setattr("vps.openscap.subprocess.run", run)
    monkeypatch.setattr("vps.openscap.shutil.which", lambda name: "/usr/bin/oscap")
    monkeypatch.setattr("vps.openscap.platform.system", lambda: "Linux")
    monkeypatch.setattr("vps.openscap.platform.node", lambda: "fallback-host")
    monkeypatch.setattr(
        "vps.openscap.platform.freedesktop_os_release",
        lambda: {
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "PRETTY_NAME": "Ubuntu 24.04 LTS",
        },
    )
    monkeypatch.setattr("vps.openscap.os.geteuid", lambda: 0)
    monkeypatch.setenv("OSCAP_PROBE_ROOT", "/another-root")
    monkeypatch.setenv("OSCAP_EVALUATION_TARGET", "another-host")
    monkeypatch.setenv("OSCAP_OVAL_COMMAND_OPTIONS", "--some-extra-option")
    monkeypatch.setenv("OSCAP_CONTAINER_VARS", "OTHER=value")
    return stub


def test_native_read_only_invocation_and_actual_metadata(scanner: Scanner) -> None:
    report = assess(datastream=scanner.datastream)

    assert report == OpenScapReport(
        host="example-vps",
        system="Ubuntu 24.04 LTS",
        profile_id=PROFILE,
        profile_title="CIS Example Level 1 Server",
        benchmark_version="0.1.82",
        engine_version="1.3.9",
        privileged=True,
        findings=(
            OpenScapFinding(
                id=RULE,
                title="Disable SSH Root Login",
                references=("CIS 5.1.20",),
                status="pass",
                severity="medium",
                evidence="OpenSCAP reported a pass.",
                remediation=(
                    "The root account is privileged.\n\n"
                    "Set PermitRootLogin no in the SSH configuration.\n\n"
                    "Check the configuration before reloading SSH."
                ),
            ),
        ),
        profile_version="1.0.0",
    )
    assert report.verdict == Verdict.BASELINE_PASSED
    (command,) = scanner.calls
    assert command == [
        "/usr/bin/oscap",
        "xccdf",
        "eval",
        "--profile",
        PROFILE,
        "--results",
        str(scanner.directories[0] / "results.xml"),
        str(scanner.datastream),
    ]
    assert not scanner.directories[0].exists()


@pytest.mark.parametrize("profile", ["cis_level1_server", PROFILE])
def test_custom_executable_and_profile(scanner: Scanner, profile: str) -> None:
    report = assess(
        oscap=Path("local-oscap"), datastream=scanner.datastream, profile=profile
    )

    assert report.profile_id == PROFILE
    assert scanner.calls[0][0] == str(Path("local-oscap").resolve())


def test_failed_rules_are_valid_with_exit_two(scanner: Scanner) -> None:
    scanner.exit = 2
    scanner.result_xml = results(
        "fail", "notselected", attributes="severity='critical'"
    )

    report = assess(datastream=scanner.datastream)

    assert report.verdict == Verdict.ACTION_NEEDED
    assert len(report.findings) == 1
    assert report.findings[0].severity == "unknown"
    assert report.findings[0].evidence == "OpenSCAP supplied no rule-specific evidence."


@pytest.mark.parametrize(
    ("statuses", "privileged", "verdict"),
    [
        (("pass", "notapplicable"), True, Verdict.BASELINE_PASSED),
        (("pass",), False, Verdict.INCOMPLETE),
        (("notapplicable",), True, Verdict.INCOMPLETE),
        (("error", "pass"), True, Verdict.INCOMPLETE),
        (("unknown", "pass"), True, Verdict.INCOMPLETE),
        (("notchecked", "pass"), True, Verdict.INCOMPLETE),
        (("informational", "pass"), True, Verdict.INCOMPLETE),
        (("fixed", "pass"), True, Verdict.INCOMPLETE),
        (("fail", "error"), False, Verdict.ACTION_NEEDED),
    ],
)
def test_verdict_requires_verified_privileged_passes(
    scanner: Scanner,
    statuses: tuple[str, ...],
    privileged: bool,
    verdict: Verdict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vps.openscap.os.geteuid", lambda: 0 if privileged else 1000)
    scanner.result_xml = results(*statuses)

    report = assess(datastream=scanner.datastream)

    assert tuple(f.status for f in report.findings) == statuses
    assert report.verdict == verdict
    assert replace(report, findings=()).verdict == Verdict.INCOMPLETE


def test_effective_uid_limits_privilege_even_with_root_result(
    scanner: Scanner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vps.openscap.os.geteuid", lambda: 1000)
    scanner.result_xml = results(
        "pass", identity='<identity privileged="true">root</identity>'
    )

    assert assess(datastream=scanner.datastream).verdict == Verdict.INCOMPLETE


def test_meaningful_messages_and_fixtext_preserve_paragraphs(scanner: Scanner) -> None:
    scanner.result_xml = results(
        "error",
        messages="<message severity='error'>Permission denied reading evidence.</message>"
        "<message>Review scanner privileges.</message>",
    )
    scanner.datastream.write_text(
        content(
            description="<description>Rationale only.</description>"
            "<fixtext><h:p>Set the root setting to <sub idref='root_value'/>.</h:p>"
            "<h:p>Review the new configuration.</h:p></fixtext>"
        )
    )

    (finding,) = assess(datastream=scanner.datastream).findings

    assert finding.evidence == (
        "Permission denied reading evidence.\n\nReview scanner privileges."
    )
    assert finding.remediation == (
        "Set the root setting to no.\n\nReview the new configuration."
    )


def test_remediation_preserves_config_lines(scanner: Scanner) -> None:
    scanner.result_xml = results("fail")
    scanner.datastream.write_text(
        content(
            description="<description>Set these values in the configuration file."
            "<h:pre>\n  [xdmcp]\n  Enable=false\n</h:pre></description>"
        )
    )

    (finding,) = assess(datastream=scanner.datastream).findings

    assert (
        finding.remediation
        == "Set these values in the configuration file.\n\n[xdmcp]\nEnable=false"
    )


@pytest.mark.parametrize(
    "description",
    [
        "<description>Background about the security policy.</description>",
        "<description>Administrators should understand how to install packages.</description>",
        "<description>Set the value to <sub idref='missing_value'/>.</description>",
    ],
)
def test_rationale_and_unresolved_values_are_not_remediation(
    scanner: Scanner, description: str
) -> None:
    scanner.datastream.write_text(content(description=description))

    assert assess(datastream=scanner.datastream).findings[0].remediation is None


def test_engine_version_falls_back_to_result_cpe(scanner: Scanner) -> None:
    scanner.result_xml = results("pass", scanner="").replace(
        "<TestResult id='result'>",
        "<TestResult id='result' test-system='cpe:/a:redhat:openscap:1.4.0'>",
    )

    assert assess(datastream=scanner.datastream).engine_version == "1.4.0"


def test_missing_optional_versions_remain_unknown(scanner: Scanner) -> None:
    scanner.result_xml = results("pass", scanner="")
    scanner.datastream.write_text(
        content()
        .replace("<version>0.1.82</version>", "")
        .replace("<version>1.0.0</version>", "")
    )

    report = assess(datastream=scanner.datastream)

    assert report.engine_version is None
    assert report.benchmark_version is None
    assert report.profile_version is None


def test_default_content_matches_exact_distribution(
    scanner: Scanner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "vps.openscap._CONTENT_DIRECTORIES", (scanner.datastream.parent,)
    )

    assert assess().profile_id == PROFILE

    scanner.datastream.rename(scanner.datastream.with_name("ssg-ubuntu2204-ds.xml"))
    with pytest.raises(OpenScapError, match=r"Ubuntu 24\.04.*--datastream"):
        assess()


@pytest.mark.parametrize(
    ("distro", "version", "filename"),
    [
        ("debian", "12", "ssg-debian12-ds.xml"),
        ("rhel", "9.4", "ssg-rhel9-ds.xml"),
        ("almalinux", "9.4", "ssg-almalinux9-ds.xml"),
        ("ol", "9.4", "ssg-ol9-ds.xml"),
        ("sles", "15.6", "ssg-sle15-ds.xml"),
        ("fedora", "42", "ssg-fedora-ds.xml"),
    ],
)
def test_distro_specific_default_paths(
    scanner: Scanner,
    monkeypatch: pytest.MonkeyPatch,
    distro: str,
    version: str,
    filename: str,
) -> None:
    monkeypatch.setattr(
        "vps.openscap.platform.freedesktop_os_release",
        lambda: {"ID": distro, "VERSION_ID": version},
    )
    monkeypatch.setattr(
        "vps.openscap._CONTENT_DIRECTORIES", (scanner.datastream.parent,)
    )
    scanner.datastream.rename(scanner.datastream.with_name(filename))

    assert assess().profile_id == PROFILE


def test_os_release_unavailable_still_allows_explicit_content(
    scanner: Scanner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> dict[str, str]:
        raise OSError("release unavailable")

    monkeypatch.setattr("vps.openscap.platform.freedesktop_os_release", unavailable)

    assert assess(datastream=scanner.datastream).system == "Linux"
    with pytest.raises(OpenScapError, match="--datastream"):
        assess()


def test_missing_scanner_and_unsupported_host_are_actionable(
    scanner: Scanner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vps.openscap.shutil.which", lambda name: None)
    with pytest.raises(OpenScapError, match="sudo apt install openscap-scanner"):
        assess(datastream=scanner.datastream)
    monkeypatch.setattr("vps.openscap.platform.system", lambda: "Darwin")
    with pytest.raises(OpenScapError, match="require Linux"):
        assess(datastream=scanner.datastream)
    assert not scanner.calls


@pytest.mark.parametrize(
    "exception",
    [
        PermissionError("Permission denied"),
        FileNotFoundError("No such file"),
        OSError("Cannot execute"),
    ],
)
def test_execution_boundary_failures_are_wrapped(
    scanner: Scanner, exception: Exception
) -> None:
    scanner.exception = exception
    with pytest.raises(OpenScapError, match="OpenSCAP"):
        assess(datastream=scanner.datastream)
    assert all(not directory.exists() for directory in scanner.directories)


def test_error_exit_contains_concise_diagnostics(scanner: Scanner) -> None:
    scanner.exit = 1
    scanner.stderr = "The local content cannot be evaluated.\n" + "detail " * 1000

    with pytest.raises(
        OpenScapError, match=r"status 1.*cannot be evaluated"
    ) as failure:
        assess(datastream=scanner.datastream)

    assert len(str(failure.value)) < 2100
    assert all(not directory.exists() for directory in scanner.directories)


@pytest.mark.parametrize(
    ("xml", "message"),
    [
        ("not XML", "Cannot read OpenSCAP XCCDF results"),
        (f'<Benchmark xmlns="{NAMESPACE}"/>', "exactly one"),
        (results("pass", profile="wrong"), "unexpected profile"),
        (results("pass", rule_id="wrong"), "unknown rule"),
        (results("unexpected"), "invalid rule result"),
        (results("notselected"), "no selected rule results"),
    ],
)
def test_unusable_results_never_become_a_pass(
    scanner: Scanner, xml: str, message: str
) -> None:
    scanner.result_xml = xml
    with pytest.raises(OpenScapError, match=message):
        assess(datastream=scanner.datastream)


def test_invalid_or_unreadable_content_prevents_execution(scanner: Scanner) -> None:
    scanner.datastream.write_text("invalid XML")
    with pytest.raises(OpenScapError, match=r"SCAP content.*--datastream"):
        assess(datastream=scanner.datastream)
    scanner.datastream.unlink()
    with pytest.raises(OpenScapError, match=r"SCAP content.*--datastream"):
        assess(datastream=scanner.datastream)
    assert not scanner.calls


@pytest.mark.parametrize(
    "profiles",
    [
        "<Profile id='another'><title>Another benchmark</title></Profile>",
        f"<Profile id='{PROFILE}'/><Profile id='{PROFILE}'/>",
    ],
)
def test_missing_or_ambiguous_profiles_prevent_execution(
    scanner: Scanner, profiles: str
) -> None:
    scanner.datastream.write_text(content(profiles=profiles))
    with pytest.raises(OpenScapError, match=r"[Pp]rofile"):
        assess(datastream=scanner.datastream)
    assert not scanner.calls


@pytest.mark.parametrize("suffix", ["cis_level1_server", "cis_server_l1"])
def test_common_default_cis_profile_names(scanner: Scanner, suffix: str) -> None:
    alternate = f"xccdf_org.ssgproject.content_profile_{suffix}"
    scanner.datastream.write_text(content().replace(PROFILE, alternate))
    scanner.result_xml = results("pass", profile=alternate)

    assert assess(datastream=scanner.datastream).profile_id == alternate


def test_generic_cis_profile_requires_explicit_selection(scanner: Scanner) -> None:
    alternate = "xccdf_org.ssgproject.content_profile_cis"
    scanner.datastream.write_text(content().replace(PROFILE, alternate))
    scanner.result_xml = results("pass", profile=alternate)

    with pytest.raises(OpenScapError, match="CIS Level 1 Server profile"):
        assess(datastream=scanner.datastream)

    assert assess(datastream=scanner.datastream, profile="cis").profile_id == alternate


@pytest.mark.parametrize("option", ["oscap", "datastream"])
def test_unresolvable_user_paths_are_setup_errors(
    scanner: Scanner, option: str
) -> None:
    paths = {"datastream": scanner.datastream, option: Path("~vps_missing_user/audit")}

    with pytest.raises(OpenScapError, match=f"Cannot resolve --{option} path"):
        assess(**paths)

    assert not scanner.calls


def test_xccdf_11_content_and_results(scanner: Scanner) -> None:
    old_namespace = "http://checklists.nist.gov/xccdf/1.1"
    scanner.datastream.write_text(content().replace(NAMESPACE, old_namespace))
    scanner.result_xml = results("pass").replace(NAMESPACE, old_namespace)

    assert assess(datastream=scanner.datastream).verdict == Verdict.BASELINE_PASSED
