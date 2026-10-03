"""Unit tests for collected file permission and ownership checks."""

import stat

from accesslens.checks.file_check import run
from accesslens.models import FileRecord, ScanContext, UserRecord, GroupRecord


def context(**kwargs):
    """Build a minimal context for file checks."""

    return ScanContext(
        "host",
        "kernel",
        "time",
        "tester",
        False,
        users=[UserRecord("root", 0, 0, "/root", "/bin/bash")],
        groups=[GroupRecord("root", 0, [])],
        **kwargs,
    )


def test_file_checks_report_expected_risks():
    findings = run(
        context(
            world_writable_files=[FileRecord("/etc/unsafe", 0o100666, 0, 0, False, False)],
            world_writable_dirs_no_sticky=[FileRecord("/tmp/open", 0o40777, 0, 0, True, False)],
            sensitive_files={
                "/etc/passwd": FileRecord("/etc/passwd", 0o100666, 0, 0, False, False)
            },
            ssh_files=[
                FileRecord("/home/alice/.ssh", 0o40755, 1000, 1000, True, False),
                FileRecord("/home/alice/.ssh/id_rsa", 0o100644, 1000, 1000, False, False),
                FileRecord("/home/alice/.ssh/authorized_keys", 0o100664, 1000, 1000, False, False),
            ],
            orphan_files=[FileRecord("/opt/orphan", 0o100644, 9999, 9999, False, False)],
        )
    )
    assert {
        "FIL-001", "FIL-002", "FIL-003", "FIL-004", "FIL-005", "FIL-006", "FIL-007"
    } <= {item.check_id for item in findings}


def test_clean_file_checks_report_no_findings():
    assert run(
        context(
            sensitive_files={
                "/etc/passwd": FileRecord("/etc/passwd", 0o100644, 0, 0, False, False)
            }
        )
    ) == []
