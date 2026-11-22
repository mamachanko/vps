import sys
from contextlib import AbstractContextManager, nullcontext

from rich.console import Console


def terminal_text(value: str, encoding: str | None = "utf-8") -> str:
    """Escape characters that could change terminal layout or execute controls."""
    escaped = "".join(
        character
        if character.isprintable()
        else character.encode("unicode_escape").decode("ascii")
        for character in value
    )
    encoding = encoding or "utf-8"
    return escaped.encode(encoding, errors="backslashreplace").decode(encoding)


def terminal_status(
    message: str, *, active: bool = True
) -> AbstractContextManager[object]:
    if active and sys.stderr.isatty():
        console = Console(stderr=True)
        if console.is_interactive:
            return console.status(message, spinner="line")
    return nullcontext()
