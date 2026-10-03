"""Unit tests for SUID/SGID checks."""

from accesslens.checks.suid_check import run
from accesslens.models import FileRecord, ScanContext


def context(records):
    """Build a minimal context for SUID checks."""

    return ScanContext("host", "kernel", "time", "tester", False, suid_sgid_files=records)


def test_suid_checks_report_dangerous_unknown_and_summary():
    findings = run(
        context(
            [
                FileRecord("/opt/find", 0o104755, 0, 0, False, False),
                FileRecord("/opt/custom-helper", 0o102755, 1000, 1000, False, False),
            ]
        )
    )
    check_ids = {item.check_id for item in findings}
    assert {"SID-001", "SID-002", "SID-003"} <= check_ids
    assert next(item for item in findings if item.check_id == "SID-001").severity == "CRITICAL"


def test_clean_suid_checks_report_no_findings_for_empty_scan():
    assert run(context([])) == []
