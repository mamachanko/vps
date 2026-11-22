import platform
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vps.audit import Verdict, collect_audit
from vps.audit_output import audit_json, print_audit
from vps.disk import inspect_disk
from vps.disk_output import print_report, report_json
from vps.terminal import terminal_status, terminal_text

app = typer.Typer(
    name="vps",
    help="Inspect a Unix server from the terminal.",
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
    pretty_exceptions_enable=False,
)


@app.callback()
def main(
    ctx: typer.Context,
    show_version: Annotated[
        bool, typer.Option("--version", help="Show the installed version.")
    ] = (False),
) -> None:
    if show_version:
        typer.echo(f"vps {version('vps')}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help(), nl=False)


@app.command()
def disk(
    path: Annotated[
        Path,
        typer.Argument(
            help="File or directory on the filesystem to inspect.", metavar="PATH"
        ),
    ] = Path("/"),
    top: Annotated[
        int | None,
        typer.Option(
            "--top",
            min=1,
            metavar="N",
            help="Scan a directory and show its N largest children.",
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print a machine-readable report.")
    ] = False,
) -> None:
    """Show filesystem capacity, with an optional allocated-space scan."""
    try:
        with terminal_status("Scanning disk usage...", active=top is not None):
            report = inspect_disk(path, top)
    except OSError as error:
        if top is not None and isinstance(error, NotADirectoryError):
            raise typer.BadParameter(
                "--top requires a directory.", param_hint="PATH"
            ) from error
        typer.echo(f"Error: {terminal_text(str(error), sys.stderr.encoding)}", err=True)
        raise typer.Exit(1) from error

    if json_output:
        typer.echo(report_json(report))
    else:
        print_report(report, Console())
    if report.scan is not None and report.scan.issue_count:
        count = report.scan.issue_count
        noun = "entry" if count == 1 else "entries"
        typer.echo(f"Warning: partial scan. Could not read {count} {noun}.", err=True)
        raise typer.Exit(3)


@app.command()
def audit(
    json_output: Annotated[
        bool, typer.Option("--json", help="Print a machine-readable report.")
    ] = False,
) -> None:
    """Check a Linux VPS for common hardening gaps."""
    if platform.system() != "Linux":
        typer.echo(
            "Security audit requires Linux. Run vps audit on the VPS you want to check.",
            err=True,
        )
        raise typer.Exit(2)

    with terminal_status("Checking server hardening..."):
        report = collect_audit()

    if json_output:
        typer.echo(audit_json(report))
    else:
        print_audit(report, Console())
    raise typer.Exit(
        {
            Verdict.BASELINE_PASSED: 0,
            Verdict.ACTION_NEEDED: 1,
            Verdict.REVIEW_NEEDED: 1,
            Verdict.INCOMPLETE: 3,
        }[report.verdict]
    )
