"""Render a scan result as a readable terminal report."""

import sys

from ..config import SEVERITY_LEVELS, TOOL_NAME
from ..models import Finding, ScanContext
from ..scoring import ScoreResult


_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
}
_RESET = "\033[0m"


def _severity_key(item: Finding) -> int:
    """Return the configured severity ordering index for sorting."""

    return SEVERITY_LEVELS.index(item.severity)


def render(
    context: ScanContext,
    findings: list[Finding],
    score: ScoreResult,
    no_color: bool = False,
    stream=None,
) -> None:
    """Print the complete terminal summary and ranked findings."""

    output = stream or sys.stdout
    use_color = not no_color and getattr(output, "isatty", lambda: False)()
    print(f"{TOOL_NAME.upper()} - Linux Privilege & Permission Risk Analyzer", file=output)
    print(
        f"Host: {context.hostname}  Kernel: {context.kernel}  "
        f"Run as: {context.run_as_user}{' (root)' if context.is_root else ''}  "
        f"Time: {context.scan_time}",
        file=output,
    )
    print("-" * 78, file=output)
    print(f"RISK SCORE: {score.value} / 100     GRADE: {score.grade}", file=output)
    print(
        "  ".join(f"{severity}: {score.counts.get(severity, 0)}" for severity in SEVERITY_LEVELS),
        file=output,
    )
    print("-" * 78, file=output)

    for item in sorted(findings, key=lambda finding: (_severity_key(finding), finding.check_id, finding.target)):
        label = f"[{item.severity}]"
        if use_color:
            label = f"{_COLORS.get(item.severity, '')}{label}{_RESET}"
        print(f"{label:<20} {item.check_id}  {item.title}", file=output)
        print(f"             {item.target}", file=output)
        print(f"             {item.description}", file=output)
        print(f"             Fix: {item.fix_command}", file=output)

    print("-" * 78, file=output)
    if context.skipped:
        print("SKIPPED:", file=output)
        for message in context.skipped:
            print(f"  - {message}", file=output)
    else:
        print("SKIPPED: (none)", file=output)
    print("Read-only audit. Fix commands are suggestions - review before running.", file=output)
