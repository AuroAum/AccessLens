"""Unit tests for sudo rule and sudoers file checks."""

import os

from accesslens.checks.sudo_check import run
from accesslens.models import ScanContext, SudoRule


def context(rules):
    """Build a minimal context for sudo checks."""

    return ScanContext("host", "kernel", "time", "tester", False, sudo_rules=rules)


def test_sudo_checks_report_rule_risks(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("alice ALL=(ALL) NOPASSWD: ALL\nbob ALL=(ALL) NOPASSWD: /usr/bin/id\ncarol ALL=(ALL) ALL\n")
    os.chmod(sudoers, 0o644)
    rules = [
        SudoRule(str(sudoers), 1, "alice ALL=(ALL) NOPASSWD: ALL"),
        SudoRule(str(sudoers), 2, "bob ALL=(ALL) NOPASSWD: /usr/bin/id"),
        SudoRule(str(sudoers), 3, "carol ALL=(ALL) ALL"),
    ]
    findings = run(context(rules))
    check_ids = {item.check_id for item in findings}
    assert {"SUD-001", "SUD-002", "SUD-003", "SUD-004"} <= check_ids


def test_clean_sudo_checks_report_no_findings(tmp_path):
    del tmp_path
    assert run(context([SudoRule("/nonexistent/sudoers", 1, "%sudo ALL=(ALL:ALL) ALL")])) == []
