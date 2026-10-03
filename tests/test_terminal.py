"""Unit tests for terminal report rendering."""

from io import StringIO

from accesslens.models import Finding, ScanContext
from accesslens.reporters.terminal import render
from accesslens.scoring import calculate_score


def test_terminal_report_contains_summary_and_finding():
    context = ScanContext("demo", "6.8", "now", "tester", False, skipped=["shadow unavailable"])
    finding = Finding("USR-001", "UID 0 account", "Users", "CRITICAL", "evil", "description", "why", "fix", "evidence")
    output = StringIO()
    render(context, [finding], calculate_score([finding]), no_color=True, stream=output)
    report = output.getvalue()
    assert "RISK SCORE: 75 / 100" in report
    assert "USR-001" in report
    assert "shadow unavailable" in report
