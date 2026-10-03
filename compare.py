"""Compare two AccessLens JSON reports by stable finding identity."""

from dataclasses import dataclass
from typing import Any

from .reporters.json_report import load


@dataclass
class Comparison:
    """The changes and score delta between two reports."""

    before_score: int
    after_score: int
    new: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    unchanged: list[dict[str, Any]]

    @property
    def score_delta(self) -> int:
        """Return the later score minus the earlier score."""

        return self.after_score - self.before_score


def compare_payloads(
    before: dict[str, Any],
    after: dict[str, Any],
) -> Comparison:
    """Compare already-loaded report payloads using ``(check_id, target)``."""

    before_items = {
        (item["check_id"], item["target"]): item for item in before["findings"]
    }
    after_items = {
        (item["check_id"], item["target"]): item for item in after["findings"]
    }
    before_keys = set(before_items)
    after_keys = set(after_items)
    return Comparison(
        before_score=int(before["score"]["value"]),
        after_score=int(after["score"]["value"]),
        new=[after_items[key] for key in sorted(after_keys - before_keys)],
        resolved=[before_items[key] for key in sorted(before_keys - after_keys)],
        unchanged=[after_items[key] for key in sorted(before_keys & after_keys)],
    )


def compare_files(before_path: str, after_path: str) -> Comparison:
    """Load two JSON reports and compare them."""

    return compare_payloads(load(before_path), load(after_path))
