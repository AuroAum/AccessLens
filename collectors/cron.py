"""Parse root cron schedules and inspect standard root cron directories."""

from pathlib import Path
import shlex

from ..config import CRON_DIRECTORIES
from ..models import CronEntry, ScanContext


def _note(context: ScanContext, message: str) -> None:
    """Record a non-fatal cron read or parse issue."""

    context.skipped.append(message)


def _script_path(command: str) -> str | None:
    """Return the first absolute command token, if one exists."""

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return next((token for token in tokens if token.startswith("/")), None)


def _parse_crontab(path: Path, context: ScanContext) -> None:
    """Parse one system crontab in the six-field format."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, PermissionError, IsADirectoryError, UnicodeError) as error:
        _note(context, f"Skipped {path}: {error}")
        return
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("@"):
            continue
        if "=" in stripped.split(None, 1)[0]:
            continue
        fields = stripped.split(None, 6)
        if len(fields) < 7:
            _note(context, f"Skipped malformed cron entry {path}:{line_number}")
            continue
        user, command = fields[5], fields[6]
        if user == "root":
            context.cron_entries.append(
                CronEntry(str(path), user, command, _script_path(command))
            )


def collect_cron(context: ScanContext, etc_dir: str = "/etc") -> ScanContext:
    """Collect root entries from crontab, cron.d, and periodic cron folders."""

    etc = Path(etc_dir)
    _parse_crontab(etc / "crontab", context)
    cron_d = etc / "cron.d"
    try:
        entries = sorted(cron_d.iterdir())
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        entries = []
    for entry in entries:
        if entry.is_file():
            _parse_crontab(entry, context)

    for directory in CRON_DIRECTORIES:
        periodic = Path(directory)
        if etc_dir != "/etc":
            periodic = etc / Path(directory).relative_to("/etc")
        try:
            entries = sorted(periodic.iterdir())
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
        for entry in entries:
            if entry.is_file() and not entry.name.startswith("."):
                context.cron_entries.append(
                    CronEntry(str(entry), "root", str(entry), str(entry))
                )
    return context
