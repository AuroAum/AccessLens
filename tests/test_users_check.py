"""Unit tests for user, shadow, UID, shell, and group checks."""

from accesslens.checks.users_check import run
from accesslens.models import (
    GroupRecord,
    ScanContext,
    ShadowRecord,
    UserRecord,
)


def context(users, groups=(), shadow=None):
    """Build the smallest context needed by the user checks."""

    return ScanContext("host", "kernel", "time", "tester", False, users=list(users), groups=list(groups), shadow=shadow)


def test_user_checks_report_expected_risks():
    findings = run(
        context(
            [
                UserRecord("root-copy", 0, 0, "/root-copy", "/bin/bash"),
                UserRecord("service", 50, 50, "/srv/service", "/bin/bash"),
                UserRecord("same-id", 1000, 1000, "/home/same-id", "/bin/bash"),
                UserRecord("same-id-two", 1000, 1000, "/home/same-id-two", "/bin/bash"),
            ],
            [GroupRecord("sudo", 27, ["service"])],
            [ShadowRecord("service", "")],
        )
    )
    check_ids = {item.check_id for item in findings}
    assert {"USR-001", "USR-002", "USR-003", "USR-004", "GRP-001"} <= check_ids


def test_clean_user_checks_report_no_findings():
    findings = run(
        context(
            [UserRecord("root", 0, 0, "/root", "/bin/bash"), UserRecord("alice", 1000, 1000, "/home/alice", "/bin/bash")],
            [GroupRecord("users", 100, [])],
            [ShadowRecord("alice", "$6$hash")],
        )
    )
    assert findings == []
