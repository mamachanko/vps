import json
from collections import Counter
from dataclasses import asdict

from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from vps.audit import Verdict
from vps.openscap import OpenScapFinding, OpenScapReport
from vps.terminal import terminal_text

_VERDICTS = {
    Verdict.ACTION_NEEDED: ("ACTION NEEDED", "red"),
    Verdict.BASELINE_PASSED: ("PROFILE PASSED", "green"),
    Verdict.INCOMPLETE: ("AUDIT INCOMPLETE", "yellow"),
}
_STATUSES = {
    "fail": ("FAIL", "red"),
    "error": ("ERROR", "yellow"),
    "unknown": ("UNKNOWN", "yellow"),
    "notchecked": ("NOT CHECKED", "yellow"),
    "informational": ("INFO", "yellow"),
    "fixed": ("FIXED", "yellow"),
    "pass": ("PASS", "green"),
    "notapplicable": ("N/A", "dim"),
}
_SEVERITIES = {
    "high": ("HIGH", "bright_red"),
    "medium": ("MEDIUM", "yellow"),
    "low": ("LOW", "cyan"),
    "unknown": ("UNRATED", "dim"),
}
_STATUS_ORDER = {"fail": 0, "pass": 2, "notapplicable": 3}
_SEVERITY_ORDER = {severity: rank for rank, severity in enumerate(_SEVERITIES)}
_RESOLVED = {"pass", "notapplicable"}
_BRIEF_LIMIT = 6
_NEEDS_PRIVILEGES = (
    "Run the audit with root privileges to check settings that require elevated access."
)


def _hint(finding: OpenScapFinding, *, privileged: bool) -> str | None:
    if finding.status == "fail" and not finding.remediation:
        return "Look up this rule in the benchmark for remediation guidance."
    if finding.status not in _RESOLVED | {"fail"}:
        if finding.status in {"error", "unknown"} and not privileged:
            return _NEEDS_PRIVILEGES
        return "Review the rule and verify its requirements on this host."
    return None


def _order(finding: OpenScapFinding) -> tuple[int, int]:
    return _STATUS_ORDER.get(finding.status, 1), _SEVERITY_ORDER.get(
        finding.severity, 3
    )


def openscap_json(report: OpenScapReport) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "engine": "openscap",
            "engine_version": report.engine_version,
            "host": report.host,
            "system": report.system,
            "profile": {
                "id": report.profile_id,
                "title": report.profile_title,
                "version": report.profile_version,
            },
            "benchmark_version": report.benchmark_version,
            "privileged": report.privileged,
            "verdict": report.verdict,
            "summary": dict(sorted(Counter(f.status for f in report.findings).items())),
            "findings": [
                asdict(finding) | {"hint": _hint(finding, privileged=report.privileged)}
                for finding in sorted(report.findings, key=_order)
            ],
        }
    )


def print_openscap(
    report: OpenScapReport, console: Console, *, show_all: bool = False
) -> None:
    verdict, verdict_color = _VERDICTS[report.verdict]
    profile = report.profile_title
    if report.profile_id in {
        "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "xccdf_org.ssgproject.content_profile_cis_server_l1",
    }:
        profile = "CIS Level 1 Server"
        if report.profile_version:
            profile += f" v{report.profile_version.removeprefix('v')}"
    heading = f"OpenSCAP / {report.system} / {profile}"
    console.print(
        Text.assemble(
            (verdict, f"bold {verdict_color}"),
            "  ",
            (terminal_text(heading, console.encoding), "bold"),
        )
    )
    source = [report.host]
    if report.engine_version:
        source.append(f"OpenSCAP {report.engine_version}")
    if report.benchmark_version:
        source.append(f"Content {report.benchmark_version}")
    source.append("Root" if report.privileged else "Unprivileged")
    console.print(Text(terminal_text(" / ".join(source), console.encoding), "dim"))

    findings = sorted(report.findings, key=_order)
    counts = Counter(finding.status for finding in findings)
    triage = [finding for finding in findings if finding.status not in _RESOLVED]
    summary = (
        (counts["fail"], "failed", "red"),
        (len(triage) - counts["fail"], "unverified", "yellow"),
        (counts["pass"], "passed", "green"),
        (counts["notapplicable"], "not applicable", "dim"),
    )
    console.print(
        Text("   ").join(
            Text(f"{count} {label}", color) for count, label, color in summary
        )
    )

    for finding in findings if show_all else triage[:_BRIEF_LIMIT]:
        console.print()
        _print_finding(finding, console, privileged=report.privileged)

    if not show_all and len(triage) > _BRIEF_LIMIT:
        console.print()
        console.print(
            Text.assemble(
                (
                    f"Showing {_BRIEF_LIMIT} of {len(triage)} findings needing attention. ",
                    "dim",
                ),
                ("Use --all to see every check.", "bold"),
            )
        )
    coverage = None
    if not triage and counts["pass"] == 0:
        coverage = "No checks applied. Confirm the data stream matches this system."
    elif not report.privileged:
        coverage = _NEEDS_PRIVILEGES
    if coverage:
        console.print()
        console.print(Text.assemble(("Coverage  ", "bold"), (coverage, "dim")))


def _detail_text(value: str, console: Console) -> Text:
    return Text(
        "\n".join(terminal_text(line, console.encoding) for line in value.split("\n"))
    )


def _print_finding(
    finding: OpenScapFinding, console: Console, *, privileged: bool
) -> None:
    status, status_color = _STATUSES.get(finding.status, ("UNVERIFIED", "yellow"))
    severity, severity_color = _SEVERITIES.get(finding.severity, _SEVERITIES["unknown"])
    badge = Text(status, f"bold {status_color}")
    title = Text(terminal_text(finding.title, console.encoding), "bold")
    rating = Text(severity, f"bold {severity_color}")
    indent = 13 if console.width >= 65 else 0
    if indent:
        heading = Table.grid(padding=(0, 2, 0, 0), expand=True)
        heading.add_column(width=11)
        heading.add_column(ratio=1, overflow="fold")
        heading.add_column(justify="right", no_wrap=True)
        heading.add_row(badge, title, rating)
        console.print(heading)
    else:
        console.print(Text.assemble(badge, "  ", title, "  ", rating))

    reference = (
        "  /  ".join(finding.references)
        if finding.references
        else finding.id.removeprefix("xccdf_org.ssgproject.content_rule_")
    )
    console.print(
        Padding(
            Text(terminal_text(reference, console.encoding), "dim"), (0, 0, 0, indent)
        )
    )

    details = Table.grid(padding=(0, 2, 0, 0))
    details.add_column(width=11)
    details.add_column(ratio=1, overflow="fold")
    details.add_row(Text("Evidence", "bold"), _detail_text(finding.evidence, console))
    if finding.status == "fail" and finding.remediation:
        label, guidance = "Remediation", finding.remediation
    else:
        label, guidance = "Hint", _hint(finding, privileged=privileged)
    if guidance:
        details.add_row(Text(label, "bold cyan"), _detail_text(guidance, console))
    console.print(Padding(details, (0, 0, 0, indent)))
