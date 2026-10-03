"""Dataclasses used to move collected facts and findings through AccessLens.

Keeping the model layer free of scanning logic makes the rest of the tool
easier to test and lets reporters consume the same structured result.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """One security observation and its human-readable remediation advice."""

    check_id: str
    title: str
    category: str
    severity: str
    target: str
    description: str
    why_risky: str
    fix_command: str
    evidence: str


@dataclass
class FileRecord:
    """Metadata collected for one filesystem entry."""

    path: str
    mode: int
    uid: int
    gid: int
    is_dir: bool
    is_symlink: bool


@dataclass
class UserRecord:
    """A single entry from the system passwd database."""

    name: str
    uid: int
    gid: int
    home: str
    shell: str


@dataclass
class GroupRecord:
    """A single entry from the system group database."""

    name: str
    gid: int
    members: list[str] = field(default_factory=list)


@dataclass
class ShadowRecord:
    """The username and password-field status from shadow."""

    name: str
    password_field: str


@dataclass
class SudoRule:
    """One non-comment sudoers rule with its source location."""

    source_file: str
    line_number: int
    raw_text: str


@dataclass
class CronEntry:
    """A root-owned scheduled command and its discovered script path."""

    source_file: str
    user: str
    command: str
    script_path: Optional[str] = None


@dataclass
class ScanContext:
    """All raw facts collected during one local system scan."""

    hostname: str
    kernel: str
    scan_time: str
    run_as_user: str
    is_root: bool
    scan_paths: list[str] = field(default_factory=list)
    users: list[UserRecord] = field(default_factory=list)
    groups: list[GroupRecord] = field(default_factory=list)
    shadow: Optional[list[ShadowRecord]] = None
    sudo_rules: Optional[list[SudoRule]] = None
    world_writable_files: list[FileRecord] = field(default_factory=list)
    world_writable_dirs_no_sticky: list[FileRecord] = field(default_factory=list)
    suid_sgid_files: list[FileRecord] = field(default_factory=list)
    orphan_files: list[FileRecord] = field(default_factory=list)
    cron_entries: list[CronEntry] = field(default_factory=list)
    ssh_files: list[FileRecord] = field(default_factory=list)
    sensitive_files: dict[str, Optional[FileRecord]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
