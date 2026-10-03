"""Calculate explainable risk scores from structured findings."""

from collections import Counter
from dataclasses import dataclass

from .config import SEVERITY_CAPS, SEVERITY_LEVELS, SEVERITY_WEIGHTS
from .models import Finding


@dataclass
class ScoreResult:
    """Score, grade, and count information used by reporters."""

    value: int
    grade: str
    counts: dict[str, int]
    category_counts: dict[str, int]
    penalties: dict[str, int]


def grade_for_score(score: int) -> str:
    """Convert a numeric score into the documented A-F grade."""

    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def calculate_score(findings: list[Finding]) -> ScoreResult:
    """Apply weighted, per-check-capped penalties and return a score result."""

    counts = {severity: 0 for severity in SEVERITY_LEVELS}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1

    category_counts = dict(Counter(item.category for item in findings))
    by_check: dict[str, list[Finding]] = {}
    for item in findings:
        by_check.setdefault(item.check_id, []).append(item)

    penalties: dict[str, int] = {}
    for check_id, check_findings in by_check.items():
        highest = min(
            check_findings,
            key=lambda item: SEVERITY_LEVELS.index(item.severity),
        ).severity
        raw_penalty = sum(SEVERITY_WEIGHTS.get(item.severity, 0) for item in check_findings)
        penalties[check_id] = min(raw_penalty, SEVERITY_CAPS.get(highest, 0))

    score = max(0, 100 - sum(penalties.values()))
    return ScoreResult(
        value=score,
        grade=grade_for_score(score),
        counts=counts,
        category_counts=category_counts,
        penalties=penalties,
    )
