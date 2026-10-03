"""Unit tests for escaped, self-contained HTML reports."""

from accesslens.models import Finding, ScanContext
from accesslens.reporters.html_report import render
from accesslens.scoring import calculate_score


def test_html_escapes_untrusted_values_and_includes_controls():
    """Targets and fixes must be escaped while report controls remain present."""

    item = Finding(
        "FIL-001",
        "Unsafe <file>",
        "Files",
        "HIGH",
        "/tmp/a'><script>alert(1)</script>",
        "description",
        "why",
        "chmod 600 '/tmp/a'",
        "evidence",
    )
    context = ScanContext("demo", "kernel", "time", "tester", False)
    html = render(context, [item], calculate_score([item]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "data-filter=\"HIGH\"" in html
    assert "copy-fix" in html
    assert "navigator.clipboard" in html
