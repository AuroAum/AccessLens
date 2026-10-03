"""Unit tests for score weights, caps, floors, and grade boundaries."""

from accesslens.models import Finding
from accesslens.scoring import calculate_score, grade_for_score


def item(check_id="X-001", severity="HIGH", category="Files"):
    """Build a compact test finding."""

    return Finding(check_id, "title", category, severity, "target", "description", "why", "fix", "evidence")


def test_empty_findings_get_perfect_score():
    result = calculate_score([])
    assert result.value == 100
    assert result.grade == "A"
    assert all(value == 0 for value in result.counts.values())


def test_penalty_is_capped_per_check():
    result = calculate_score([item() for _ in range(20)])
    assert result.value == 75
    assert result.penalties == {"X-001": 25}


def test_score_floor_and_grade_boundaries():
    result = calculate_score([item(f"X-{number:03}", "CRITICAL") for number in range(10)])
    assert result.value == 0
    assert result.grade == "F"
    assert [grade_for_score(score) for score in (100, 90, 89, 75, 74, 60, 59, 40, 39)] == [
        "A", "A", "B", "B", "C", "C", "D", "D", "F"
    ]
