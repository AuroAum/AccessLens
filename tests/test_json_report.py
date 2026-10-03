"""Unit tests for JSON report serialization and loading."""

from pathlib import Path

from accesslens.models import Finding, ScanContext
from accesslens.reporters.json_report import load, save
from accesslens.scoring import calculate_score


def test_json_report_round_trips(tmp_path: Path):
    """Saved reports contain the documented metadata and finding fields."""

    context = ScanContext("demo", "kernel", "time", "tester", False, scan_paths=["/tmp"])
    item = Finding("FIL-001", "Unsafe", "Files", "HIGH", "/tmp/x", "desc", "why", "fix", "mode")
    path = tmp_path / "scan.json"
    save(path, context, [item], calculate_score([item]))
    payload = load(path)
    assert payload["tool"] == "AccessLens"
    assert payload["scan"]["paths"] == ["/tmp"]
    assert payload["findings"][0]["check_id"] == "FIL-001"
    assert payload["score"]["value"] == 90


def test_json_loader_rejects_other_documents(tmp_path: Path):
    """A random JSON object must not be accepted as an AccessLens report."""

    path = tmp_path / "invalid.json"
    path.write_text('{"hello": "world"}', encoding="utf-8")
    try:
        load(path)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid report was accepted")
