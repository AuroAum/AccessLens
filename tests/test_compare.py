"""Unit tests for JSON scan comparison."""

from accesslens.compare import compare_payloads


def item(check_id, target, severity="HIGH"):
    """Build the compact report finding shape used by comparisons."""

    return {
        "check_id": check_id,
        "target": target,
        "severity": severity,
        "title": "Finding",
    }


def report(score, findings):
    """Build a minimal valid report payload."""

    return {"tool": "AccessLens", "scan": {}, "score": {"value": score}, "findings": findings}


def test_compare_finds_new_resolved_and_unchanged_items():
    before = report(
        50,
        [item("A", "/same"), item("B", "/resolved"), item("C", "/changed", "MEDIUM")],
    )
    after = report(
        80,
        [item("A", "/same", "LOW"), item("D", "/new"), item("C", "/changed", "HIGH")],
    )
    result = compare_payloads(before, after)
    assert result.score_delta == 30
    assert {(x["check_id"], x["target"]) for x in result.new} == {("D", "/new")}
    assert {(x["check_id"], x["target"]) for x in result.resolved} == {("B", "/resolved")}
    assert {(x["check_id"], x["target"]) for x in result.unchanged} == {
        ("A", "/same"),
        ("C", "/changed"),
    }
