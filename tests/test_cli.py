from importlib.metadata import version

from typer.testing import CliRunner

from vps.cli import app


def test_version() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == f"vps {version('vps')}\n"


def test_no_arguments_shows_help() -> None:
    result = CliRunner().invoke(app, [])

    assert result.exit_code == 0
    assert "Inspect a Unix server" in result.stdout
