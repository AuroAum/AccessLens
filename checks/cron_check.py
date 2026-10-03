"""Evaluate whether root cron commands can be modified by non-root users."""

import os
import stat

from ..models import Finding, ScanContext
from ..utils import mode_to_octal, quote_path
from .helpers import finding


def _metadata(path: str):
    """Read metadata without following a script symlink."""

    try:
        return os.lstat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def run(context: ScanContext) -> list[Finding]:
    """Return findings for writable root cron scripts and directories."""

    findings: list[Finding] = []
    for entry in context.cron_entries:
        if not entry.script_path:
            continue
        script = _metadata(entry.script_path)
        if script is not None and stat.S_ISREG(script.st_mode):
            mode = stat.S_IMODE(script.st_mode)
            if mode & 0o022:
                severity = "CRITICAL" if mode & 0o002 else "HIGH"
                findings.append(
                    finding(
                        "CRN-001",
                        "Root cron job runs a writable script",
                        "Cron",
                        severity,
                        entry.script_path,
                        f"Root cron entry {entry.source_file} runs a script writable by non-root users.",
                        "Anyone who edits the script may execute code as root at the next scheduled run.",
                        f"sudo chmod go-w {quote_path(entry.script_path)}; sudo chown root:root {quote_path(entry.script_path)}",
                        f"mode={mode_to_octal(script.st_mode)} source={entry.source_file}",
                    )
                )

        parent = os.path.dirname(entry.script_path) or "."
        directory = _metadata(parent)
        if directory is not None:
            directory_mode = stat.S_IMODE(directory.st_mode)
            unsafe_directory = (
                (directory_mode & stat.S_IWOTH and not directory_mode & stat.S_ISVTX)
                or parent in {"/tmp", "/var/tmp"}
            )
            if unsafe_directory:
                findings.append(
                    finding(
                        "CRN-002",
                        "Root cron script is in an unsafe directory",
                        "Cron",
                        "HIGH",
                        entry.script_path,
                        f"The root cron script is located in {parent}, which non-root users may manipulate.",
                        "An attacker may replace the script or its path and obtain root code execution.",
                        f"sudo chmod o-w {quote_path(parent)}",
                        f"directory_mode={directory_mode:04o} source={entry.source_file}",
                    )
                )

        periodic_name = os.path.basename(os.path.dirname(entry.source_file))
        if periodic_name in {"cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"}:
            if script is not None and stat.S_IMODE(script.st_mode) & 0o022:
                findings.append(
                    finding(
                        "CRN-003",
                        "Periodic root cron script is writable",
                        "Cron",
                        "HIGH",
                        entry.script_path,
                        "A script in a root-run periodic cron directory is writable by group or others.",
                        "A non-root user could alter a script that the system executes as root.",
                        f"sudo chmod go-w {quote_path(entry.script_path)}",
                        f"mode={mode_to_octal(script.st_mode)}",
                    )
                )
    return findings
