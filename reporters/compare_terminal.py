"""Render scan comparison results in the terminal."""

from ..config import TOOL_NAME
from ..compare import Comparison


def render(comparison: Comparison, stream=None) -> None:
    """Print score change and each finding change category."""

    import sys

    output = stream or sys.stdout
    sign = "+" if comparison.score_delta >= 0 else ""
    print(f"{TOOL_NAME} comparison", file=output)
    print(
        f"Score: {comparison.before_score} -> {comparison.after_score} "
        f"({sign}{comparison.score_delta})",
        file=output,
    )
    for label, items in (
        ("NEW", comparison.new),
        ("RESOLVED", comparison.resolved),
        ("UNCHANGED", comparison.unchanged),
    ):
        print(f"\n{label}: {len(items)}", file=output)
        for item in items:
            print(
                f"  [{item['severity']}] {item['check_id']} {item['target']} - {item['title']}",
                file=output,
            )
