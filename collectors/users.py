"""Read Linux passwd, group, and shadow databases into typed records.

These parsers accept file paths so unit tests can use harmless fixtures instead
of depending on the host machine. They only read files and never modify them.
"""

from pathlib import Path

try:
    from ..models import GroupRecord, ShadowRecord, UserRecord
except ImportError:
    from models import GroupRecord, ShadowRecord, UserRecord


def _note(skipped: list[str] | None, message: str) -> None:
    """Add a non-fatal collection problem to the caller's skipped list."""

    if skipped is not None:
        skipped.append(message)


def _read_lines(path: str, skipped: list[str] | None) -> list[str] | None:
    """Read text lines, converting expected access failures into skip notes."""

    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, PermissionError, IsADirectoryError) as error:
        _note(skipped, f"Skipped {path}: {error.strerror or 'file cannot be read'}")
        return None
    except UnicodeError as error:
        _note(skipped, f"Skipped {path}: invalid text encoding ({error})")
        return None


def parse_passwd(
    path: str = "/etc/passwd", skipped: list[str] | None = None
) -> list[UserRecord] | None:
    """Parse ``name:x:uid:gid:comment:home:shell`` passwd records."""

    lines = _read_lines(path, skipped)
    if lines is None:
        return None

    users: list[UserRecord] = []
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            _note(skipped, f"Skipped malformed passwd entry {path}:{line_number}")
            continue
        try:
            users.append(
                UserRecord(
                    name=fields[0],
                    uid=int(fields[2]),
                    gid=int(fields[3]),
                    home=fields[5],
                    shell=fields[6],
                )
            )
        except ValueError:
            _note(skipped, f"Skipped passwd entry with invalid UID/GID {path}:{line_number}")
    return users


def parse_group(
    path: str = "/etc/group", skipped: list[str] | None = None
) -> list[GroupRecord] | None:
    """Parse ``name:x:gid:member1,member2`` group records."""

    lines = _read_lines(path, skipped)
    if lines is None:
        return None

    groups: list[GroupRecord] = []
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            _note(skipped, f"Skipped malformed group entry {path}:{line_number}")
            continue
        try:
            members = [member for member in fields[3].split(",") if member]
            groups.append(GroupRecord(fields[0], int(fields[2]), members))
        except ValueError:
            _note(skipped, f"Skipped group entry with invalid GID {path}:{line_number}")
    return groups


def parse_shadow(
    path: str = "/etc/shadow", skipped: list[str] | None = None
) -> list[ShadowRecord] | None:
    """Parse shadow usernames and password fields when access is permitted."""

    lines = _read_lines(path, skipped)
    if lines is None:
        return None

    records: list[ShadowRecord] = []
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            _note(skipped, f"Skipped malformed shadow entry {path}:{line_number}")
            continue
        records.append(ShadowRecord(name=fields[0], password_field=fields[1]))
    return records
