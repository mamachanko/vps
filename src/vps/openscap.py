"""Run an installed OpenSCAP assessment without remediation or remote fetching."""

import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from xml.etree import ElementTree as ET

from vps.audit import Verdict

_XCCDF_NAMESPACES = (
    "http://checklists.nist.gov/xccdf/1.2",
    "http://checklists.nist.gov/xccdf/1.1",
)
_CONTENT_DIRECTORIES = (
    Path("/usr/share/xml/scap/ssg/content"),
    Path("/usr/share/scap-security-guide"),
    Path("/usr/share/openscap/ssg/content"),
)
_RESULT_STATUSES = {
    "pass",
    "fail",
    "error",
    "unknown",
    "notapplicable",
    "notchecked",
    "notselected",
    "informational",
    "fixed",
}
_BLOCKS = {"p", "div", "pre", "li", "br", "ul", "ol"}


class OpenScapError(Exception):
    """An installed scanner or its content could not produce an assessment."""


@dataclass(frozen=True)
class OpenScapFinding:
    id: str
    title: str
    references: tuple[str, ...]
    status: str
    severity: str
    evidence: str
    remediation: str | None


@dataclass(frozen=True)
class OpenScapReport:
    host: str
    system: str
    profile_id: str
    profile_title: str
    benchmark_version: str | None
    engine_version: str | None
    privileged: bool
    findings: tuple[OpenScapFinding, ...]
    profile_version: str | None = None

    @property
    def verdict(self) -> Verdict:
        statuses = {finding.status for finding in self.findings}
        if "fail" in statuses:
            return Verdict.ACTION_NEEDED
        if (
            not self.privileged
            or "pass" not in statuses
            or statuses - {"pass", "notapplicable"}
        ):
            return Verdict.INCOMPLETE
        return Verdict.BASELINE_PASSED


def _text(node: ET.Element | None, values: dict[str, str] | None = None) -> str:
    if node is None:
        return ""
    pieces: list[str] = []
    paragraphs: list[str] = []

    def flush(*, literal: bool = False) -> None:
        text = "".join(pieces)
        pieces.clear()
        if literal:
            if block := dedent(text).strip("\n"):
                paragraphs.append(block)
            return
        paragraphs.extend(
            paragraph
            for part in text.split("\n\n")
            if (paragraph := " ".join(part.split()))
        )

    def visit(element: ET.Element, *, literal: bool = False) -> None:
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "sub":
            if values is None or element.get("idref") not in values:
                raise KeyError(element.get("idref"))
            pieces.append(values[element.get("idref", "")])
            return
        block = tag in _BLOCKS and not literal
        if block:
            flush()
        literal = literal or tag == "pre"
        pieces.append(element.text or "")
        for child in element:
            visit(child, literal=literal)
            pieces.append(child.tail or "")
        if block:
            flush(literal=literal)

    try:
        visit(node)
    except KeyError:
        return ""
    flush()
    return "\n\n".join(paragraphs)


def _read_xml(path: Path, description: str) -> ET.Element:
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise OpenScapError(
            f"Cannot read {description} at {path}: {error}. "
            "Use a readable, valid local SCAP datastream with --datastream."
        ) from error


def _resolve_path(path: Path, option: str) -> Path:
    try:
        return path.expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise OpenScapError(f"Cannot resolve {option} path {path}: {error}") from error


def _default_datastream(release: dict[str, str]) -> Path:
    distro = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    major = version.split(".")[0]
    products = {
        "ubuntu": f"ubuntu{version.replace('.', '')}",
        "debian": f"debian{major}",
        "rhel": f"rhel{major}",
        "centos": f"centos{major}",
        "almalinux": f"almalinux{major}",
        "ol": f"ol{major}",
        "sles": f"sle{major}",
        "fedora": "fedora",
    }
    product = products.get(distro) if version else None
    if product and re.fullmatch(r"[a-z]+[0-9]*", product):
        for directory in _CONTENT_DIRECTORIES:
            candidate = directory / f"ssg-{product}-ds.xml"
            if candidate.is_file():
                return candidate
    name = release.get("PRETTY_NAME", f"{distro} {version}".strip()) or "this system"
    raise OpenScapError(
        f"No installed SCAP datastream found for {name}. Install matching "
        "SCAP Security Guide content, or pass its local XML path with --datastream."
    )


def _select_profile(
    content: ET.Element, requested: str | None
) -> tuple[ET.Element, ET.Element, dict[str, str]]:
    profiles = [
        (benchmark, profile, {"x": namespace})
        for namespace in _XCCDF_NAMESPACES
        for benchmark in content.iter(f"{{{namespace}}}Benchmark")
        for profile in benchmark.findall(f"{{{namespace}}}Profile")
    ]
    candidates = (
        (requested,)
        if requested
        else (
            "cis_level1_server",
            "cis_server_l1",
        )
    )
    for candidate in candidates:
        matches = [
            entry
            for entry in profiles
            if entry[1].get("id") == candidate
            or entry[1].get("id", "").endswith(f"_profile_{candidate}")
        ]
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise OpenScapError(
                f"Profile {candidate!r} is ambiguous in this datastream. "
                "Use content containing a single matching benchmark."
            )
    label = f"Profile {requested!r}" if requested else "A CIS Level 1 Server profile"
    raise OpenScapError(
        f"{label} was not found in the local datastream. "
        "List installed profiles with oscap info DATASTREAM and choose --profile."
    )


def _remediation(
    rule: ET.Element, ns: dict[str, str], values: dict[str, str]
) -> str | None:
    fixtext = _text(rule.find("x:fixtext", ns), values)
    if fixtext:
        return fixtext
    description = _text(rule.find("x:description", ns), values)
    if re.search(
        r"(?:^|[.!?:]\s+|\n\n)(?:(?:to|using)\s+[^.!?\n]{1,180},\s*)?"
        r"(?:add|set|configure|install|remove|disable|enable|ensure|modify|edit|"
        r"change|create|correct|run|replace|update|generate)\b"
        r"|\b(?:can|should|must) be (?:installed|removed|configured) with "
        r"the following command\b",
        description,
        re.IGNORECASE,
    ):
        return description
    return None


def _findings(
    result: ET.Element, benchmark: ET.Element, ns: dict[str, str]
) -> tuple[OpenScapFinding, ...]:
    values = {
        value.get("idref", ""): _text(value)
        for value in result.findall("x:set-value", ns)
    }
    rules = {rule.get("id"): rule for rule in benchmark.findall(".//x:Rule", ns)}
    findings = []
    for row in result.findall("x:rule-result", ns):
        status = _text(row.find("x:result", ns))
        if status not in _RESULT_STATUSES:
            raise OpenScapError(
                f"OpenSCAP returned an invalid rule result: {status!r}."
            )
        if status == "notselected":
            continue
        rule_id = row.get("idref", "")
        rule = rules.get(rule_id)
        if rule is None:
            raise OpenScapError(f"OpenSCAP returned an unknown rule: {rule_id!r}.")
        severity = row.get("severity", rule.get("severity", "unknown"))
        messages = [_text(message) for message in row.findall("x:message", ns)]
        evidence = "\n\n".join(message for message in messages if message)
        if not evidence:
            evidence = {
                "pass": "OpenSCAP reported a pass.",
                "fail": "OpenSCAP supplied no rule-specific evidence.",
                "notapplicable": "OpenSCAP reported this rule as not applicable.",
                "notchecked": "This rule was not checked by OpenSCAP.",
            }.get(status, f"OpenSCAP reported {status}; this rule was not verified.")
        references = tuple(
            dict.fromkeys(
                f"CIS {reference}"
                for node in rule.findall("x:reference", ns)
                if re.match(
                    r"https?://(?:www\.)?cisecurity\.org/benchmark(?:/|$)",
                    node.get("href", ""),
                )
                if (reference := _text(node))
            )
        )
        findings.append(
            OpenScapFinding(
                id=rule_id,
                title=_text(rule.find("x:title", ns)) or rule_id,
                references=references,
                status=status,
                severity=severity
                if severity in {"high", "medium", "low"}
                else "unknown",
                evidence=evidence,
                remediation=_remediation(rule, ns, values),
            )
        )
    if not findings:
        raise OpenScapError(
            "OpenSCAP returned no selected rule results for this profile."
        )
    return tuple(findings)


def _evaluate(executable: str, datastream: Path, profile_id: str) -> ET.Element:
    with tempfile.TemporaryDirectory(prefix="vps-openscap-") as directory:
        results = Path(directory) / "results.xml"
        plugins = Path(directory) / "plugins"
        plugins.mkdir()
        env = os.environ.copy()
        for name in (
            "OSCAP_PROBE_ROOT",
            "OSCAP_EVALUATION_TARGET",
            "OSCAP_OVAL_COMMAND_OPTIONS",
            "OSCAP_CONTAINER_VARS",
        ):
            env.pop(name, None)
        env.update(LC_ALL="C", LANG="C", OSCAP_CHECK_ENGINE_PLUGIN_DIR=str(plugins))
        command = [
            executable,
            "xccdf",
            "eval",
            "--profile",
            profile_id,
            "--results",
            str(results),
            str(datastream),
        ]
        with tempfile.TemporaryFile(
            mode="w+", encoding="utf-8", errors="replace"
        ) as diagnostics:
            try:
                run = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=diagnostics,
                    env=env,
                    check=False,
                )
            except OSError as error:
                raise OpenScapError(
                    f"Cannot execute OpenSCAP at {executable}: {error}. "
                    "Install an OpenSCAP scanner or choose its executable with --oscap."
                ) from error
            if run.returncode not in (0, 2):
                diagnostics.seek(0)
                detail = " ".join(diagnostics.read(2000).split())
                raise OpenScapError(
                    f"OpenSCAP evaluation exited with status {run.returncode}."
                    + (f" {detail}" if detail else " Check the scanner and content.")
                )
        return _read_xml(results, "OpenSCAP XCCDF results")


def assess(
    *,
    oscap: Path | None = None,
    datastream: Path | None = None,
    profile: str | None = None,
) -> OpenScapReport:
    if platform.system() != "Linux":
        raise OpenScapError("OpenSCAP host assessments require Linux.")
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        release = {}
    executable = (
        str(_resolve_path(oscap, "--oscap")) if oscap else shutil.which("oscap")
    )
    if executable is None:
        install = (
            "Install it with sudo apt install openscap-scanner"
            if release.get("ID") in {"ubuntu", "debian"}
            else "Install an OpenSCAP scanner"
        )
        raise OpenScapError(
            "OpenSCAP (oscap) is not installed or is absent from PATH. "
            f"{install}, or choose its executable with --oscap."
        )
    datastream = _resolve_path(
        datastream or _default_datastream(release), "--datastream"
    )
    benchmark, selected, ns = _select_profile(
        _read_xml(datastream, "SCAP content"), profile
    )
    profile_id = selected.get("id", "")
    try:
        root = _evaluate(executable, datastream, profile_id)
    except OSError as error:
        raise OpenScapError(
            f"Cannot create temporary OpenSCAP assessment files: {error}"
        ) from error
    results = list(root.iter(f"{{{ns['x']}}}TestResult"))
    if len(results) != 1:
        raise OpenScapError("OpenSCAP did not return exactly one XCCDF assessment.")
    result = results[0]
    result_profile = result.find("x:profile", ns)
    if result_profile is None or result_profile.get("idref") != profile_id:
        raise OpenScapError("OpenSCAP results identify an unexpected profile.")
    engine_version = next(
        (
            _text(fact)
            for fact in result.findall("x:target-facts/x:fact", ns)
            if fact.get("name") == "urn:xccdf:fact:scanner:version" and _text(fact)
        ),
        None,
    )
    if engine_version is None:
        match = re.search(r":openscap:([^:]+)", result.get("test-system", ""))
        engine_version = match[1] if match else None
    return OpenScapReport(
        host=_text(result.find("x:target", ns)) or platform.node(),
        system=release.get("PRETTY_NAME", platform.system()),
        profile_id=profile_id,
        profile_title=_text(selected.find("x:title", ns)) or profile_id,
        benchmark_version=_text(benchmark.find("x:version", ns)) or None,
        engine_version=engine_version,
        privileged=os.geteuid() == 0,
        findings=_findings(result, benchmark, ns),
        profile_version=_text(selected.find("x:version", ns)) or None,
    )
