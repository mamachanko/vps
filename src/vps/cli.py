"""Command-line entry point for vps."""

from importlib.metadata import version
from typing import Annotated

import typer

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
