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
from vps.openscap import OpenScapError, assess
from vps.openscap_output import openscap_json, print_openscap
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
    fast: Annotated[
        bool, typer.Option("--fast", help="Run five local checks without OpenSCAP.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print a machine-readable report.")
    ] = False,
    show_all: Annotated[
        bool, typer.Option("--all", help="Show every selected OpenSCAP check.")
    ] = False,
    datastream: Annotated[
        Path | None,
        typer.Option("--datastream", help="Path to a local SCAP data stream."),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="OpenSCAP profile ID or unique suffix."),
    ] = None,
    oscap: Annotated[
        Path | None, typer.Option("--oscap", help="Path to the oscap executable.")
    ] = None,
) -> None:
    """Assess Linux hardening with OpenSCAP."""
    if platform.system() != "Linux":
        typer.echo(
            "Security audit requires Linux. Run vps audit on the VPS you want to check.",
            err=True,
        )
        raise typer.Exit(2)

    if fast:
        if (
            show_all
            or datastream is not None
            or profile is not None
            or oscap is not None
        ):
            raise typer.BadParameter(
                "Use --all, --datastream, --profile, and --oscap with OpenSCAP mode.",
                param_hint="--fast",
            )
        with terminal_status("Checking server hardening..."):
            quick_report = collect_audit()
        if json_output:
            typer.echo(audit_json(quick_report))
        else:
            print_audit(quick_report, Console())
        verdict = quick_report.verdict
    else:
        try:
            with terminal_status("Running OpenSCAP assessment..."):
                report = assess(oscap=oscap, datastream=datastream, profile=profile)
        except OpenScapError as error:
            diagnostic = terminal_text(str(error), sys.stderr.encoding)
            typer.echo(f"OpenSCAP audit: {diagnostic}", err=True)
            raise typer.Exit(2) from error
        if json_output:
            typer.echo(openscap_json(report))
        else:
            print_openscap(report, Console(), show_all=show_all)
        verdict = report.verdict

    raise typer.Exit(
        {
            Verdict.BASELINE_PASSED: 0,
            Verdict.ACTION_NEEDED: 1,
            Verdict.REVIEW_NEEDED: 1,
            Verdict.INCOMPLETE: 3,
        }[verdict]
    )
