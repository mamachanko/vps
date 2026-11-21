import errno
import json
import os
import resource
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.text import Text
from typer.testing import CliRunner

from vps.cli import app
from vps.disk import inspect_disk


@pytest.fixture
def capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    result = os.statvfs_result((4096, 1024, 1000, 400, 300, 0, 0, 0, 0, 255))
    monkeypatch.setattr(os, "statvfs", lambda path: result)
    monkeypatch.setattr(os, "fstatvfs", lambda descriptor: result)


def test_json_capacity_defaults_to_root(capacity: None) -> None:
    result = CliRunner().invoke(app, ["disk", "--json"])

    assert result.exit_code == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "schema_version": 1,
        "path": "/",
        "filesystem": {
            "total_bytes": 1024000,
            "used_bytes": 614400,
            "available_bytes": 307200,
            "reserved_bytes": 102400,
            "used_percent": 66.7,
        },
        "scan": None,
    }


@pytest.mark.parametrize(
    ("fragment", "available", "free", "total", "expected"),
    [
        (0, 3, 4, 10, (40960, 24576, 12288, 4096, 66.7)),
        (1024, -2, 4, 10, (10240, 6144, 0, 4096, 100.0)),
        (1024, 0, 0, 0, (0, 0, 0, 0, 0.0)),
    ],
)
def test_capacity_edge_cases(
    monkeypatch: pytest.MonkeyPatch,
    fragment: int,
    available: int,
    free: int,
    total: int,
    expected: tuple[int, int, int, int, float],
) -> None:
    result = os.statvfs_result(
        (4096, fragment, total, free, available, 0, 0, 0, 0, 255)
    )
    monkeypatch.setattr(os, "statvfs", lambda path: result)

    usage = inspect_disk(Path("/")).filesystem

    assert (
        usage.total_bytes,
        usage.used_bytes,
        usage.available_bytes,
        usage.reserved_bytes,
        usage.used_percent,
    ) == expected


def test_capacity_accepts_file_without_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file = tmp_path / "file"
    file.write_text("content")

    def forbidden_scan(*args: object, **kwargs: object) -> None:
        pytest.fail("capacity-only inspection must not scan directories")

    monkeypatch.setattr(os, "scandir", forbidden_scan)

    result = CliRunner().invoke(app, ["disk", str(file), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["path"] == str(file)
    assert json.loads(result.stdout)["scan"] is None


def test_top_ranks_allocated_space_and_includes_directory_metadata(
    tmp_path: Path,
) -> None:
    large = tmp_path / "large"
    large.mkdir()
    nested = large / "data"
    nested.write_bytes(b"x" * 65536)
    small = tmp_path / "small"
    small.write_bytes(b"x")

    result = CliRunner().invoke(app, ["disk", str(tmp_path), "--top", "1", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["scan"] == {
        "entries": [
            {
                "name": "large",
                "allocated_bytes": (large.stat().st_blocks + nested.stat().st_blocks)
                * 512,
            }
        ],
        "skipped_other_devices": 0,
        "issue_count": 0,
        "issues": [],
    }


def test_sparse_files_use_allocated_space_and_ties_sort_by_name(tmp_path: Path) -> None:
    for name in ("zeta", "alpha"):
        with (tmp_path / name).open("wb") as file:
            file.truncate(16 * 1024 * 1024)
    expected = (tmp_path / "alpha").stat().st_blocks * 512

    report = inspect_disk(tmp_path, top=2)

    assert report.scan is not None
    assert [(entry.name, entry.allocated_bytes) for entry in report.scan.entries] == [
        ("alpha", expected),
        ("zeta", expected),
    ]
    assert expected < 16 * 1024 * 1024


def test_hard_links_belong_to_lexically_first_top_level_child(tmp_path: Path) -> None:
    later = tmp_path / "zeta"
    later.mkdir()
    payload = later / "data"
    payload.write_bytes(b"x" * 65536)
    earlier = tmp_path / "alpha"
    earlier.mkdir()
    (earlier / "link").hardlink_to(payload)
    (earlier / "another-link").hardlink_to(payload)

    report = inspect_disk(tmp_path, top=2)

    assert report.scan is not None
    assert {entry.name: entry.allocated_bytes for entry in report.scan.entries} == {
        "alpha": (earlier.stat().st_blocks + payload.stat().st_blocks) * 512,
        "zeta": later.stat().st_blocks * 512,
    }


def test_child_symlinks_are_not_followed_but_root_symlink_is(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "data").write_bytes(b"x" * 65536)
    child_link = root / "link"
    child_link.symlink_to(outside, target_is_directory=True)
    (root / "loop").symlink_to(root, target_is_directory=True)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(root, target_is_directory=True)

    report = inspect_disk(root_link, top=10)

    assert report.path == root_link
    assert report.scan is not None
    assert {entry.name: entry.allocated_bytes for entry in report.scan.entries} == {
        "link": child_link.lstat().st_blocks * 512,
        "loop": (root / "loop").lstat().st_blocks * 512,
    }
    assert report.scan.issue_count == 0


def test_empty_directory_has_clear_human_output(tmp_path: Path, capacity: None) -> None:
    result = CliRunner().invoke(app, ["disk", str(tmp_path), "--top", "3"])

    assert result.exit_code == 0
    assert "Directory is empty." in result.stdout
    assert "% used" in result.stdout
    assert "available" in result.stdout
    assert "reserved" in result.stdout


def test_human_output_escapes_filename_controls_and_rich_markup(tmp_path: Path) -> None:
    (tmp_path / "[red]file\x1b[2J\nnext\u202e").touch()

    result = CliRunner().invoke(app, ["disk", str(tmp_path), "--top", "1"])

    assert result.exit_code == 0
    assert "[red]file\\x1b[2J\\nnext\\u202e" in result.stdout
    assert "\x1b[2J" not in result.stdout
    assert "\u202e" not in result.stdout


def test_human_output_escapes_names_for_ascii_terminals(tmp_path: Path) -> None:
    (tmp_path / "caf\u00e9").touch()

    result = CliRunner(charset="ascii").invoke(
        app, ["disk", str(tmp_path), "--top", "1"]
    )

    assert result.exit_code == 0
    assert "caf\\xe9" in result.stdout


def test_error_path_is_safe_for_ascii_terminals(tmp_path: Path) -> None:
    result = CliRunner(charset="ascii").invoke(
        app, ["disk", str(tmp_path / "caf\u00e9"), "--json"]
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "caf\\xe9" in result.stderr


@pytest.mark.parametrize("arguments", [["--top", "0"], ["--top", "-1"], ["--top"]])
def test_invalid_top_is_usage_error(tmp_path: Path, arguments: list[str]) -> None:
    result = CliRunner().invoke(app, ["disk", str(tmp_path), *arguments, "--json"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Error" in result.stderr


def test_top_requires_directory(tmp_path: Path) -> None:
    file = tmp_path / "file"
    file.touch()

    result = CliRunner().invoke(app, ["disk", str(file), "--top", "1", "--json"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "--top requires a directory" in Text.from_ansi(result.stderr).plain


@pytest.mark.parametrize("arguments", [[], ["--top", "1"]])
def test_missing_root_is_fatal(tmp_path: Path, arguments: list[str]) -> None:
    result = CliRunner().invoke(
        app, ["disk", str(tmp_path / "missing"), *arguments, "--json"]
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "No such file or directory" in result.stderr
    assert "Traceback" not in result.stderr


def test_partial_scan_has_bounded_issues_and_json_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(8):
        (tmp_path / f"unreadable-{index}").touch()
    healthy = tmp_path / "healthy"
    healthy.write_bytes(b"x" * 4096)
    real_stat = os.stat

    def inaccessible(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if str(path).startswith("unreadable-") and kwargs.get("dir_fd") is not None:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", inaccessible)

    result = CliRunner().invoke(app, ["disk", str(tmp_path), "--top", "20", "--json"])

    assert result.exit_code == 3
    scan = json.loads(result.stdout)["scan"]
    assert scan["entries"][0] == {
        "name": "healthy",
        "allocated_bytes": healthy.stat().st_blocks * 512,
    }
    assert scan["issue_count"] == 8
    assert len(scan["entries"]) == 1
    assert len(scan["issues"]) == 5
    assert scan["issues"][0] == {
        "path": str(tmp_path / "unreadable-0"),
        "message": "Permission denied",
    }
    assert "partial scan" in result.stderr
    assert "8" in result.stderr


def test_other_devices_are_skipped_even_when_inode_numbers_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = tmp_path / "local"
    local.write_bytes(b"x" * 4096)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "data").write_bytes(b"x" * 65536)
    real_stat = os.stat
    local_stat = local.stat()

    def other_device(path: object, *args: object, **kwargs: object) -> object:
        metadata = real_stat(path, *args, **kwargs)
        if path == "foreign" and kwargs.get("dir_fd") is not None:
            return SimpleNamespace(
                st_dev=local_stat.st_dev + 1,
                st_ino=local_stat.st_ino,
            )
        return metadata

    monkeypatch.setattr(os, "stat", other_device)

    report = inspect_disk(tmp_path, top=10)

    assert report.scan is not None
    assert [(entry.name, entry.allocated_bytes) for entry in report.scan.entries] == [
        ("local", local_stat.st_blocks * 512)
    ]
    assert report.scan.skipped_other_devices == 1
    assert report.scan.issue_count == 0


def test_directory_swapped_for_symlink_is_not_traversed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child"
    child.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"x" * 65536)
    real_open = os.open

    def replace_with_symlink(path: object, flags: int, *args: object, **kwargs: object):
        if path == "child" and kwargs.get("dir_fd") is not None:
            child.rmdir()
            child.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_with_symlink)

    report = inspect_disk(root, top=10)

    assert report.scan is not None
    assert report.scan.issue_count == 1
    assert len(report.scan.entries) == 1
    assert report.scan.entries[0].allocated_bytes < (outside / "secret").stat().st_size


def test_opened_directory_device_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = tmp_path / "child"
    child.mkdir()
    metadata = child.stat()
    real_fstat = os.fstat

    def changed_device(descriptor: int) -> object:
        result = real_fstat(descriptor)
        if result.st_ino == metadata.st_ino:
            return SimpleNamespace(st_dev=result.st_dev + 1, st_ino=result.st_ino)
        return result

    monkeypatch.setattr(os, "fstat", changed_device)

    report = inspect_disk(tmp_path, top=10)

    assert report.scan is not None
    assert report.scan.entries == ()
    assert report.scan.skipped_other_devices == 1
    assert report.scan.issue_count == 0


def test_replaced_directory_is_reported_as_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child"
    child.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "data").write_bytes(b"x" * 65536)
    real_open = os.open

    def replace_directory(path: object, flags: int, *args: object, **kwargs: object):
        if path == "child" and kwargs.get("dir_fd") is not None:
            child.rename(tmp_path / "old")
            replacement.rename(child)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_directory)

    report = inspect_disk(root, top=10)

    assert report.scan is not None
    assert report.scan.entries == ()
    assert report.scan.issue_count == 1
    assert report.scan.issues[0].message == "Entry changed during scan"


def test_failed_child_directory_listing_keeps_metadata_and_closes_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = tmp_path / "child"
    child.mkdir()
    metadata = child.stat()
    real_open = os.open
    real_scandir = os.scandir
    descriptors = []

    def tracked_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        descriptor = real_open(path, flags, *args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def denied_listing(path: object):
        if isinstance(path, int) and os.fstat(path).st_ino == metadata.st_ino:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "scandir", denied_listing)

    report = inspect_disk(tmp_path, top=1)

    assert report.scan is not None
    assert report.scan.entries[0].allocated_bytes == metadata.st_blocks * 512
    assert report.scan.issue_count == 1
    for descriptor in descriptors:
        with pytest.raises(OSError) as failure:
            os.fstat(descriptor)
        assert failure.value.errno == errno.EBADF


def test_root_listing_failure_is_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied_listing(path: object) -> None:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "scandir", denied_listing)

    result = CliRunner().invoke(app, ["disk", str(tmp_path), "--top", "1", "--json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Permission denied" in result.stderr


def test_partial_empty_view_does_not_claim_directory_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "child").touch()
    real_stat = os.stat

    def inaccessible(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if kwargs.get("dir_fd") is not None:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", inaccessible)

    result = CliRunner().invoke(app, ["disk", str(tmp_path), "--top", "1"])

    assert result.exit_code == 3
    assert "No entries to display." in result.stdout
    assert "Directory is empty" not in result.stdout


def test_deep_tree_does_not_use_python_recursion(tmp_path: Path) -> None:
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit != resource.RLIM_INFINITY and soft_limit < 4096:
        pytest.skip("deep tree needs 4096 available file descriptors")
    descriptors = [os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)]
    try:
        for _ in range(1100):
            os.mkdir("child", dir_fd=descriptors[-1])
            descriptors.append(
                os.open("child", os.O_RDONLY | os.O_DIRECTORY, dir_fd=descriptors[-1])
            )

        report = inspect_disk(tmp_path, top=1)

        assert report.scan is not None
        assert report.scan.issue_count == 0
        assert report.scan.entries[0].allocated_bytes == sum(
            os.fstat(descriptor).st_blocks * 512 for descriptor in descriptors[1:]
        )
    finally:
        for index in range(len(descriptors) - 1, 0, -1):
            os.close(descriptors[index])
            os.rmdir("child", dir_fd=descriptors[index - 1])
        os.close(descriptors[0])
