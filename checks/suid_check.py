"""Evaluate SUID and SGID files against dangerous-program and baseline policy."""

import os
import stat

from ..config import DANGEROUS_SUID, SUID_BASELINE
from ..models import Finding, ScanContext
from ..utils import mode_to_octal, quote_path
from .helpers import finding


def run(context: ScanContext) -> list[Finding]:
    """Return dangerous, unknown, and summary findings for SUID/SGID files."""

    findings: list[Finding] = []
    for record in context.suid_sgid_files:
        mode = record.mode
        basename = os.path.basename(record.path)
        if basename in DANGEROUS_SUID:
            severity = "CRITICAL" if record.uid == 0 and mode & stat.S_ISUID else "HIGH"
            findings.append(
                finding(
                    "SID-001",
                    "SUID/SGID file on a dangerous program",
                    "SUID/SGID",
                    severity,
                    record.path,
                    f"{basename} has SUID or SGID enabled.",
                    "This program may allow a user to borrow root or group authority and spawn a privileged shell or write protected files.",
                    f"sudo chmod {'u-s' if mode & stat.S_ISUID else 'g-s'} {quote_path(record.path)}",
                    f"mode={mode_to_octal(mode)} uid={record.uid} gid={record.gid}",
                )
            )
        if record.path not in SUID_BASELINE:
            findings.append(
                finding(
                    "SID-002",
                    "SUID/SGID file is not in the known-normal baseline",
                    "SUID/SGID",
                    "MEDIUM",
                    record.path,
                    "This SUID/SGID path is not in the configured Debian/Ubuntu baseline.",
                    "Unexpected privileged binaries deserve review because they may be newly installed or malicious.",
                    f"sudo chmod u-s,g-s {quote_path(record.path)}",
                    f"mode={mode_to_octal(mode)} uid={record.uid} gid={record.gid}",
                )
            )

    if context.suid_sgid_files:
        findings.append(
            finding(
                "SID-003",
                "Count of SUID/SGID files found",
                "SUID/SGID",
                "INFO",
                "system scan",
                f"Found {len(context.suid_sgid_files)} SUID/SGID regular files.",
                "The count provides audit context and helps identify changes between scans.",
                "Review the listed SUID/SGID files against the system baseline.",
                f"count={len(context.suid_sgid_files)}",
            )
        )
    return findings
