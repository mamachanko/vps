import sys
from contextlib import nullcontext
from importlib.metadata import version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vps.disk import inspect_disk
from vps.disk_output import print_report, report_json, terminal_text

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
    progress_console = Console(stderr=True)
    progress = (
        progress_console.status("Scanning disk usage...", spinner="line")
        if top is not None and sys.stderr.isatty() and progress_console.is_interactive
        else nullcontext()
    )
    try:
        with progress:
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
