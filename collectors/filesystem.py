"""Walk selected local directories once and collect risky file metadata.

The walker uses lstat so links are observed but never followed. It also
refuses to cross filesystem boundaries, which keeps an audit of a local path
from unexpectedly traversing a mounted network or removable filesystem.
"""

import os
from pathlib import Path
import stat
import sys

from ..config import SKIP_DIRS
from ..models import FileRecord, ScanContext


def _record(path: str, metadata: os.stat_result) -> FileRecord:
    """Convert lstat metadata into the project's portable file record."""

    return FileRecord(
        path=path,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        is_dir=stat.S_ISDIR(metadata.st_mode),
        is_symlink=stat.S_ISLNK(metadata.st_mode),
    )


def _skip_directory(path: str) -> bool:
    """Return whether a directory is one of the configured skip trees."""

    candidate = Path(path)
    return any(candidate == skipped or skipped in candidate.parents for skipped in SKIP_DIRS)


def collect_filesystem(
    context: ScanContext,
    scan_paths: list[str] | None = None,
    progress_every: int = 100,
) -> ScanContext:
    """Populate filesystem risk lists in ``context`` using one directory walk."""

    paths = scan_paths or context.scan_paths
    known_uids = {user.uid for user in context.users}
    known_gids = {group.gid for group in context.groups}
    directories_seen = 0

    for start in paths:
        try:
            start_metadata = os.lstat(start)
        except (FileNotFoundError, PermissionError, OSError) as error:
            context.skipped.append(f"Skipped {start}: {error}")
            continue
        start_device = start_metadata.st_dev

        def on_error(error: OSError) -> None:
            """Record unreadable directories without aborting the full walk."""

            context.skipped.append(
                f"Skipped unreadable directory {error.filename}: {error.strerror or error}"
            )

        for root, directories, files in os.walk(
            start, topdown=True, followlinks=False, onerror=on_error
        ):
            directories_seen += 1
            if progress_every and directories_seen % progress_every == 0:
                print(
                    f"AccessLens: scanned {directories_seen} directories",
                    file=sys.stderr,
                )

            try:
                root_metadata = os.lstat(root)
            except (FileNotFoundError, PermissionError, OSError):
                directories[:] = []
                continue
            if root_metadata.st_dev != start_device or _skip_directory(root):
                directories[:] = []
                continue

            kept_directories: list[str] = []
            for directory in directories:
                full_path = os.path.join(root, directory)
                if _skip_directory(full_path):
                    continue
                try:
                    metadata = os.lstat(full_path)
                except (FileNotFoundError, PermissionError, OSError) as error:
                    context.skipped.append(f"Skipped {full_path}: {error}")
                    continue
                if metadata.st_dev == start_device and not stat.S_ISLNK(metadata.st_mode):
                    kept_directories.append(directory)
                    mode = metadata.st_mode
                    if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                        context.world_writable_dirs_no_sticky.append(
                            _record(full_path, metadata)
                        )
                    if metadata.st_uid not in known_uids or metadata.st_gid not in known_gids:
                        context.orphan_files.append(_record(full_path, metadata))
            directories[:] = kept_directories

            for filename in files:
                full_path = os.path.join(root, filename)
                try:
                    metadata = os.lstat(full_path)
                except (FileNotFoundError, PermissionError, OSError) as error:
                    context.skipped.append(f"Skipped {full_path}: {error}")
                    continue
                if metadata.st_dev != start_device or stat.S_ISLNK(metadata.st_mode):
                    continue
                mode = metadata.st_mode
                record = _record(full_path, metadata)
                if mode & stat.S_IWOTH and stat.S_ISREG(mode):
                    context.world_writable_files.append(record)
                if mode & (stat.S_ISUID | stat.S_ISGID) and stat.S_ISREG(mode):
                    context.suid_sgid_files.append(record)
                if metadata.st_uid not in known_uids or metadata.st_gid not in known_gids:
                    context.orphan_files.append(record)
    return context


def collect_sensitive_files(
    context: ScanContext, paths: tuple[str, ...] | None = None
) -> ScanContext:
    """Record metadata for configured sensitive paths when they exist."""

    for path in paths or (
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/root",
    ):
        try:
            context.sensitive_files[path] = _record(path, os.lstat(path))
        except (FileNotFoundError, PermissionError, OSError):
            context.sensitive_files[path] = None
    return context
