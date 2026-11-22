import json
from collections import Counter
from dataclasses import asdict

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vps.audit import AuditReport, Status, Verdict
from vps.terminal import terminal_text

STATUS_STYLES = {
    Status.ACTION: ("FIX", "to fix", "red"),
    Status.REVIEW: ("REVIEW", "to review", "yellow"),
    Status.UNKNOWN: ("UNVERIFIED", "unverified", "cyan"),
    Status.PASS: ("PASS", "passed", "green"),
}
VERDICT_STYLES = {
    Verdict.ACTION_NEEDED: ("Action needed", "red"),
    Verdict.REVIEW_NEEDED: ("Review needed", "yellow"),
    Verdict.INCOMPLETE: ("Audit incomplete", "cyan"),
    Verdict.BASELINE_PASSED: ("Baseline checks passed", "green"),
}
SCOPE = (
    "Local Linux baseline. Review provider firewall rules, SSH Match settings, "
    "and installed security updates separately."
)


def audit_json(report: AuditReport) -> str:
    counts = Counter(finding.status for finding in report.findings)
    return json.dumps(
        {
            "schema_version": 1,
            "host": report.host,
            "system": report.system,
            "verdict": report.verdict,
            "summary": {status: counts[status] for status in STATUS_STYLES},
            "findings": [asdict(finding) for finding in report.findings],
            "scope": SCOPE,
        }
    )


def print_audit(report: AuditReport, console: Console) -> None:
    verdict, verdict_color = VERDICT_STYLES[report.verdict]
    counts = Counter(finding.status for finding in report.findings)
    summary = Text("   ").join(
        Text(f"{counts[status]} {label}", style=color)
        for status, (_, label, color) in STATUS_STYLES.items()
        if counts[status]
    )
    host = terminal_text(report.host, console.encoding)
    system = terminal_text(report.system, console.encoding)
    console.print(
        Panel(
            Group(
                Text(verdict, style=f"bold {verdict_color}"),
                Text(f"{host}  /  {system}", style="dim"),
                Text(),
                summary,
            ),
            title="VPS quick audit",
            title_align="left",
            border_style=verdict_color,
            box=box.ASCII if console.options.ascii_only else box.ROUNDED,
            expand=False,
        )
    )
    console.print()

    compact = console.width < 55
    table = Table.grid(padding=(0, 2, 1, 0), collapse_padding=False)
    table.add_column(no_wrap=True)
    table.add_column(ratio=1)
    for finding in report.findings:
        badge, _, color = STATUS_STYLES[finding.status]
        detail = Text()
        detail.append(terminal_text(finding.title, console.encoding), style="bold")
        detail.append("\nEvidence   ", style="bold")
        detail.append(terminal_text(finding.evidence, console.encoding))
        if finding.hint:
            detail.append("\n\nNext step  ", style="bold cyan")
            detail.append(terminal_text(finding.hint, console.encoding))
        label = Text(badge, style=f"bold {color}")
        if compact:
            console.print(Text.assemble(label, "  ", detail))
            console.print()
        else:
            table.add_row(label, detail)
    if not compact:
        console.print(table)
        console.print()
    console.print(Text.assemble(("Scope  ", "bold"), (SCOPE, "dim")))
