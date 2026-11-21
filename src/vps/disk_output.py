import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vps.disk import DiskReport


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


def report_json(report: DiskReport) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "path": str(report.path),
            "filesystem": asdict(report.filesystem),
            "scan": asdict(report.scan) if report.scan is not None else None,
        }
    )


def _size(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    amount = float(value)
    units = ("KiB", "MiB", "GiB", "TiB", "PiB")
    for unit in units:
        amount /= 1024
        if amount < 1024 or unit == units[-1]:
            break
    return f"{amount:.1f} {unit}"


def print_report(report: DiskReport, console: Console) -> None:
    filesystem = report.filesystem
    console.print(
        Text("Disk", style="bold"),
        Text(terminal_text(str(report.path), console.encoding)),
    )
    color = (
        "red"
        if filesystem.used_percent >= 90
        else "yellow"
        if filesystem.used_percent >= 75
        else "green"
    )
    summary = Text()
    summary.append(f"{filesystem.used_percent:.1f}% used", style=f"bold {color}")
    if console.is_terminal and console.width >= 60:
        width = 16
        filled = round(width * filesystem.used_percent / 100)
        fill, track = ("=", "-") if console.options.ascii_only else ("█", "░")
        summary.append(f"  {fill * filled}", style=color)
        summary.append(track * (width - filled), style="dim")
    summary.append(
        f"  {_size(filesystem.used_bytes)} / {_size(filesystem.total_bytes)}"
    )
    console.print(summary)
    availability = f"{_size(filesystem.available_bytes)} available"
    if filesystem.reserved_bytes:
        availability += f"  {_size(filesystem.reserved_bytes)} reserved"
    console.print(Text(availability, style="dim"))
    if report.scan is None:
        return
    console.print()
    if report.scan.entries:
        table = Table(box=None, padding=(0, 2, 0, 0), show_edge=False)
        table.add_column("Allocated", justify="right", style="cyan", no_wrap=True)
        table.add_column("Name")
        for entry in report.scan.entries:
            table.add_row(
                _size(entry.allocated_bytes),
                Text(terminal_text(entry.name, console.encoding)),
            )
        console.print(table)
    else:
        message = (
            "No entries to display."
            if report.scan.skipped_other_devices or report.scan.issue_count
            else "Directory is empty."
        )
        console.print(message, style="dim")
    if report.scan.skipped_other_devices:
        count = report.scan.skipped_other_devices
        noun = "entry" if count == 1 else "entries"
        console.print(f"Skipped {count} {noun} on other filesystems.", style="dim")
