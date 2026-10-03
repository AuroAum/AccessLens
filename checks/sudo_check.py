"""Evaluate raw sudoers rules and sudoers file ownership/permissions."""

import os
import re
import stat

from ..models import Finding, ScanContext
from ..utils import mode_to_octal, quote_path
from .helpers import finding


_UNRESTRICTED_RULE = re.compile(r"^(?P<who>\S+)\s+ALL=\([^)]*\)\s+ALL\s*$")


def _rule_target(rule) -> str:
    """Format a sudoers source location for a finding target."""

    return f"{rule.source_file}:{rule.line_number}"


def _file_findings(context: ScanContext) -> list[Finding]:
    """Check sudoers files referenced by the collected rule sources."""

    findings: list[Finding] = []
    paths = {"/etc/sudoers"}
    if context.sudo_rules is not None:
        paths.update(rule.source_file for rule in context.sudo_rules)

    for path in sorted(paths):
        try:
            metadata = os.lstat(path)
        except (FileNotFoundError, PermissionError, OSError):
            continue
        unsafe_mode = stat.S_IMODE(metadata.st_mode) & ~0o440
        wrong_owner = metadata.st_uid != 0
        if unsafe_mode or wrong_owner:
            evidence = (
                f"mode={mode_to_octal(metadata.st_mode)} uid={metadata.st_uid} "
                f"unsafe_mode={bool(unsafe_mode)} wrong_owner={wrong_owner}"
            )
            findings.append(
                finding(
                    "SUD-004",
                    "Sudoers file has unsafe permissions",
                    "Sudo",
                    "HIGH",
                    path,
                    "A sudoers file is more permissive than the expected root-owned 0440 policy.",
                    "Users who can modify sudoers can grant themselves arbitrary root privileges.",
                    f"sudo chmod 440 {quote_path(path)}; sudo chown root:root {quote_path(path)}",
                    evidence,
                )
            )
    return findings


def run(context: ScanContext) -> list[Finding]:
    """Return findings for sudo rules and sudoers file metadata."""

    if context.sudo_rules is None:
        return _file_findings(context)

    findings: list[Finding] = []
    for rule in context.sudo_rules:
        text = rule.raw_text
        target = _rule_target(rule)
        if "NOPASSWD" in text.upper():
            severity = "HIGH" if re.search(r"\bALL\s*$", text) else "MEDIUM"
            check_id = "SUD-001" if severity == "HIGH" else "SUD-002"
            title = (
                "NOPASSWD rule granting ALL commands"
                if severity == "HIGH"
                else "NOPASSWD rule for specific commands"
            )
            findings.append(
                finding(
                    check_id,
                    title,
                    "Sudo",
                    severity,
                    target,
                    f"Sudoers rule: {text}",
                    "Passwordless sudo reduces the barrier to privileged access; some commands can also spawn a root shell.",
                    f"sudo visudo -f {quote_path(rule.source_file)}",
                    text,
                )
            )

        match = _UNRESTRICTED_RULE.match(text)
        if match and match.group("who").lstrip("%") not in {"root", "sudo", "wheel", "admin"}:
            findings.append(
                finding(
                    "SUD-003",
                    "Unrestricted sudo for a non-admin account or group",
                    "Sudo",
                    "MEDIUM",
                    target,
                    f"{match.group('who')} may run all commands through sudo.",
                    "Unrestricted sudo allows the account to obtain root privileges without a narrower operational need.",
                    f"sudo visudo -f {quote_path(rule.source_file)}",
                    text,
                )
            )

    findings.extend(_file_findings(context))
    return findings
