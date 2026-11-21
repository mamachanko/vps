import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FilesystemUsage:
    total_bytes: int
    used_bytes: int
    available_bytes: int
    reserved_bytes: int
    used_percent: float


@dataclass(frozen=True)
class DiskEntry:
    name: str
    allocated_bytes: int


@dataclass(frozen=True)
class ScanIssue:
    path: str
    message: str


@dataclass(frozen=True)
class DirectoryUsage:
    entries: tuple[DiskEntry, ...]
    skipped_other_devices: int
    issue_count: int
    issues: tuple[ScanIssue, ...]


@dataclass(frozen=True)
class DiskReport:
    path: Path
    filesystem: FilesystemUsage
    scan: DirectoryUsage | None


def inspect_disk(path: Path, top: int | None = None) -> DiskReport:
    """Read capacity, optionally ranking immediate children by allocated bytes.

    Child symlinks and other filesystems are never traversed. Hard links count
    once across the scan, in the lexically first top-level child containing them.
    Root errors propagate; child errors are recorded in the returned scan.
    """
    path = path.absolute()
    if top is None:
        return DiskReport(path, _filesystem_usage(os.statvfs(path)), None)
    if top < 1:
        raise ValueError("top must be positive")

    root_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        filesystem = _filesystem_usage(os.fstatvfs(root_fd))
        scanner = _DirectoryScanner(os.fstat(root_fd))
        with os.scandir(root_fd) as children:
            names = sorted(child.name for child in children)
        entries = []
        for name in names:
            allocated = scanner.scan_entry(root_fd, path / name)
            if allocated is not None:
                entries.append(DiskEntry(name, allocated))
        entries.sort(key=lambda entry: (-entry.allocated_bytes, entry.name))
        scan = DirectoryUsage(
            tuple(entries[:top]),
            scanner.skipped_other_devices,
            scanner.issue_count,
            tuple(scanner.issues),
        )
        return DiskReport(path, filesystem, scan)
    finally:
        os.close(root_fd)


def _filesystem_usage(filesystem: os.statvfs_result) -> FilesystemUsage:
    block_size = filesystem.f_frsize or filesystem.f_bsize
    total = filesystem.f_blocks * block_size
    free = filesystem.f_bfree * block_size
    available = max(0, filesystem.f_bavail * block_size)
    used = total - free
    denominator = used + available
    return FilesystemUsage(
        total,
        used,
        available,
        max(0, free - available),
        round(100 * used / denominator, 1) if denominator else 0.0,
    )


class _DirectoryScanner:
    def __init__(self, root: os.stat_result) -> None:
        self.device = root.st_dev
        self.seen: set[tuple[int, int]] = {(root.st_dev, root.st_ino)}
        self.skipped_other_devices = 0
        self.issue_count = 0
        self.issues: list[ScanIssue] = []

    def record_issue(self, path: Path, error: OSError | str) -> None:
        self.issue_count += 1
        if len(self.issues) < 5:
            message = (
                error.strerror or str(error) if isinstance(error, OSError) else error
            )
            self.issues.append(ScanIssue(str(path), message))

    def read_entry(self, parent_fd: int, path: Path) -> tuple[int | None, int | None]:
        try:
            metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            self.record_issue(path, error)
            return None, None
        if metadata.st_dev != self.device:
            self.skipped_other_devices += 1
            return None, None
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in self.seen:
            return 0, None
        if stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink > 1:
            self.seen.add(identity)
        allocated = metadata.st_blocks * 512
        if not stat.S_ISDIR(metadata.st_mode):
            return allocated, None

        try:
            directory_fd = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as error:
            self.record_issue(path, error)
            return allocated, None
        try:
            opened = os.fstat(directory_fd)
        except OSError as error:
            os.close(directory_fd)
            self.record_issue(path, error)
            return allocated, None
        if opened.st_dev != self.device:
            os.close(directory_fd)
            self.skipped_other_devices += 1
            return None, None
        if (opened.st_dev, opened.st_ino) != identity:
            os.close(directory_fd)
            self.record_issue(path, "Entry changed during scan")
            return None, None
        return allocated, directory_fd

    def scan_entry(self, parent_fd: int, path: Path) -> int | None:
        allocated, directory_fd = self.read_entry(parent_fd, path)
        if allocated is None:
            return None
        stack: list[tuple[int, Path, Iterator[os.DirEntry[str]], ExitStack]] = []
        try:
            while directory_fd is not None or stack:
                if directory_fd is not None:
                    resources = ExitStack()
                    resources.callback(os.close, directory_fd)
                    try:
                        children = resources.enter_context(os.scandir(directory_fd))
                    except OSError as error:
                        self.record_issue(path, error)
                        resources.close()
                    else:
                        stack.append((directory_fd, path, children, resources))
                    directory_fd = None
                if not stack:
                    break
                parent_fd, parent_path, children, resources = stack[-1]
                try:
                    child = next(children)
                except (StopIteration, OSError) as error:
                    if isinstance(error, OSError):
                        self.record_issue(parent_path, error)
                    stack.pop()
                    resources.close()
                    continue
                path = parent_path / child.name
                child_bytes, directory_fd = self.read_entry(parent_fd, path)
                if child_bytes is not None:
                    allocated += child_bytes
            return allocated
        finally:
            for _, _, _, resources in reversed(stack):
                resources.close()
