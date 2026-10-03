"""Serialize AccessLens scan results to the documented JSON report schema."""

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from ..config import TOOL_NAME, VERSION
from ..models import Finding, ScanContext
from ..scoring import ScoreResult


def build_payload(
    context: ScanContext,
    findings: list[Finding],
    score: ScoreResult,
) -> dict[str, Any]:
    """Build a JSON-compatible dictionary for one completed scan."""

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "scan": {
            "hostname": context.hostname,
            "kernel": context.kernel,
            "time": context.scan_time,
            "run_as": context.run_as_user,
            "is_root": context.is_root,
            "paths": context.scan_paths,
            "skipped": context.skipped,
        },
        "score": {
            "value": score.value,
            "grade": score.grade,
            "counts": score.counts,
            "category_counts": score.category_counts,
            "penalties": score.penalties,
        },
        "findings": [asdict(item) for item in findings],
    }


def save(
    path: str | Path,
    context: ScanContext,
    findings: list[Finding],
    score: ScoreResult,
) -> dict[str, Any]:
    """Write a complete, indented JSON report and return its payload."""

    payload = build_payload(context, findings, score)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return payload


def load(path: str | Path) -> dict[str, Any]:
    """Load and validate the top-level shape of an AccessLens JSON report."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not {"tool", "scan", "score", "findings"} <= payload.keys():
        raise ValueError("not a valid AccessLens report")
    if payload["tool"] != TOOL_NAME:
        raise ValueError(f"unsupported report tool: {payload['tool']!r}")
    return payload
