"""Evaluate collected file permissions, ownership, and SSH metadata."""

import os
import stat

from ..config import (
    ALLOWED_WORLD_WRITABLE_PATH_PREFIXES,
    SENSITIVE_FILE_POLICIES,
    SYSTEM_PATH_PREFIXES,
)
from ..models import Finding, ScanContext
from ..utils import mode_to_octal, quote_path
from .helpers import finding


def _under(path: str, prefixes: tuple[str, ...]) -> bool:
    """Return whether a path is inside one of the configured path prefixes."""

    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def run(context: ScanContext) -> list[Finding]:
    """Return findings for world-writable, sensitive, SSH, and orphan files."""

    findings: list[Finding] = []
    for record in context.world_writable_files:
        if _under(record.path, ALLOWED_WORLD_WRITABLE_PATH_PREFIXES):
            continue
        severity = "CRITICAL" if _under(record.path, SYSTEM_PATH_PREFIXES) else "HIGH"
        findings.append(
            finding(
                "FIL-001",
                "World-writable regular file",
                "Files",
                severity,
                record.path,
                "A regular file grants write permission to every local user.",
                "If a privileged process reads or executes it, an unprivileged user may influence privileged behavior.",
                f"sudo chmod o-w {quote_path(record.path)}",
                f"mode={mode_to_octal(record.mode)} uid={record.uid} gid={record.gid}",
            )
        )

    for record in context.world_writable_dirs_no_sticky:
        findings.append(
            finding(
                "FIL-002",
                "World-writable directory without sticky bit",
                "Files",
                "HIGH",
                record.path,
                "A directory is writable by everyone but does not have the sticky bit.",
                "Users may delete or rename files belonging to other users in the shared directory.",
                f"sudo chmod +t {quote_path(record.path)}",
                f"mode={mode_to_octal(record.mode)}",
            )
        )

    for path, policy in SENSITIVE_FILE_POLICIES.items():
        record = context.sensitive_files.get(path)
        if record is None:
            continue
        max_mode, severity = policy
        actual_mode = stat.S_IMODE(record.mode)
        if actual_mode & ~max_mode or record.uid != 0:
            findings.append(
                finding(
                    "FIL-003",
                    "Sensitive system file has too-permissive mode",
                    "Files",
                    severity,
                    path,
                    f"{path} is more permissive than the configured maximum or is not root-owned.",
                    "Sensitive account, authentication, and configuration files must not be writable or readable by unintended users.",
                    f"sudo chmod {format(max_mode, 'o')} {quote_path(path)}",
                    f"mode={mode_to_octal(record.mode)} uid={record.uid} max_mode={max_mode:04o}",
                )
            )

    for record in context.ssh_files:
        mode = stat.S_IMODE(record.mode)
        basename = os.path.basename(record.path)
        if basename == "authorized_keys":
            if mode & 0o022:
                findings.append(
                    finding(
                        "FIL-006",
                        "authorized_keys writable by group or others",
                        "SSH",
                        "HIGH",
                        record.path,
                        "The SSH authorized-keys file can be modified by another local user.",
                        "An attacker could add their own public key and gain persistent SSH access.",
                        f"chmod go-w {quote_path(record.path)}",
                        f"mode={mode_to_octal(record.mode)}",
                    )
                )
        elif mode & 0o077:
            findings.append(
                finding(
                    "FIL-004",
                    "SSH private key readable by group or others",
                    "SSH",
                    "HIGH",
                    record.path,
                    "An SSH private key grants read access beyond its owner.",
                    "Anyone who reads the key may authenticate as its owner to another system.",
                    f"chmod 600 {quote_path(record.path)}",
                    f"mode={mode_to_octal(record.mode)}",
                )
            )
        if record.is_dir and mode & 0o077:
            findings.append(
                finding(
                    "FIL-005",
                    ".ssh directory too open",
                    "SSH",
                    "MEDIUM",
                    record.path,
                    "The SSH configuration directory grants access to group or others.",
                    "Other users may inspect or alter SSH keys and authorization settings.",
                    f"chmod 700 {quote_path(record.path)}",
                    f"mode={mode_to_octal(record.mode)}",
                )
            )

    for record in context.orphan_files:
        findings.append(
            finding(
                "FIL-007",
                "File or directory with no valid owner or group",
                "Files",
                "MEDIUM",
                record.path,
                "The file owner or group ID is not present in the collected account databases.",
                "A future account receiving the orphaned numeric ID could silently inherit access to this item.",
                f"sudo chown root:root {quote_path(record.path)}",
                f"uid={record.uid} gid={record.gid}",
            )
        )
    return findings
