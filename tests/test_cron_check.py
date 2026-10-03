"""Unit tests for root cron collection and writeability checks."""

import os

from accesslens.checks.cron_check import run
from accesslens.collectors.cron import collect_cron
from accesslens.models import CronEntry, ScanContext


def context(entries):
    """Build a minimal context for cron checks."""

    return ScanContext("host", "kernel", "time", "tester", False, cron_entries=entries)


def test_cron_collector_keeps_root_entries_and_periodic_scripts(tmp_path):
    (tmp_path / "cron.d").mkdir()
    (tmp_path / "cron.daily").mkdir()
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/sh\n")
    os.chmod(script, 0o666)
    (tmp_path / "crontab").write_text(
        "0 3 * * * root /tmp/backup.sh\n"
        "0 4 * * * alice /tmp/not-root.sh\n"
    )
    periodic = tmp_path / "cron.daily" / "daily.sh"
    periodic.write_text("#!/bin/sh\n")
    os.chmod(periodic, 0o666)

    context_value = context([])
    collect_cron(context_value, str(tmp_path))
    assert len(context_value.cron_entries) == 2
    assert any(entry.user == "root" for entry in context_value.cron_entries)


def test_cron_checks_report_writable_script_and_directory(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    script = unsafe / "backup.sh"
    script.write_text("#!/bin/sh\n")
    os.chmod(unsafe, 0o777)
    os.chmod(script, 0o666)
    findings = run(context([CronEntry("/etc/cron.d/demo", "root", str(script), str(script))]))
    assert {"CRN-001", "CRN-002"} <= {item.check_id for item in findings}


def test_cron_checks_report_clean_script_without_findings(tmp_path):
    script = tmp_path / "backup.sh"
    script.write_text("#!/bin/sh\n")
    os.chmod(script, 0o700)
    assert run(context([CronEntry("/etc/cron.d/demo", "root", str(script), str(script))])) == []
