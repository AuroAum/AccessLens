"""Discover SSH directories and private-key authorization files read-only."""

import os
from pathlib import Path
import stat

from ..config import SSH_KEY_NAMES
from ..models import FileRecord, ScanContext


def _record(path: Path) -> FileRecord | None:
    """Return metadata for a path, or nothing when it is unavailable."""

    try:
        metadata = os.lstat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    return FileRecord(
        str(path),
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_ISDIR(metadata.st_mode),
        stat.S_ISLNK(metadata.st_mode),
    )


def collect_ssh_files(
    context: ScanContext,
    root_home: str = "/root",
    home_base: str = "/home",
) -> ScanContext:
    """Record .ssh directories and selected key files under root and homes."""

    candidates = [Path(root_home)]
    try:
        candidates.extend(
            entry for entry in Path(home_base).iterdir() if entry.is_dir()
        )
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        pass

    for home in candidates:
        ssh_directory = home / ".ssh"
        directory_record = _record(ssh_directory)
        if directory_record is None or directory_record.is_symlink:
            continue
        context.ssh_files.append(directory_record)
        try:
            entries = ssh_directory.iterdir()
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
        for entry in entries:
            if entry.name not in SSH_KEY_NAMES:
                continue
            record = _record(entry)
            if record is not None and not record.is_symlink and not record.is_dir:
                context.ssh_files.append(record)
    return context
