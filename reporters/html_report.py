"""Create a self-contained, escaped HTML report for offline review."""

from html import escape
from pathlib import Path
import json

from ..config import SEVERITY_LEVELS, TOOL_NAME, VERSION
from ..models import Finding, ScanContext
from ..scoring import ScoreResult


def _e(value: object) -> str:
    """Escape arbitrary report data before placing it into HTML."""

    return escape(str(value), quote=True)


def _finding_html(item: Finding) -> str:
    """Render one expandable finding card with safely escaped values."""

    fix_json = _e(json.dumps(item.fix_command))
    return f"""
      <article class="finding" data-severity="{_e(item.severity)}">
        <button class="finding-header" type="button" aria-expanded="false">
          <span class="badge {_e(item.severity.lower())}">{_e(item.severity)}</span>
          <strong>{_e(item.check_id)} &middot; {_e(item.title)}</strong>
          <span class="target">{_e(item.target)}</span>
        </button>
        <div class="finding-details" hidden>
          <p><b>Description:</b> {_e(item.description)}</p>
          <p><b>Why risky:</b> {_e(item.why_risky)}</p>
          <p><b>Evidence:</b> {_e(item.evidence)}</p>
          <div class="fix"><code>{_e(item.fix_command)}</code>
            <button class="copy-fix" type="button" data-fix="{fix_json}">Copy fix</button>
          </div>
        </div>
      </article>"""


def render(
    context: ScanContext,
    findings: list[Finding],
    score: ScoreResult,
) -> str:
    """Return a complete standalone HTML document for a scan."""

    cards = "\n".join(_finding_html(item) for item in findings)
    severity_cards = "".join(
        f'<div class="stat"><span>{_e(severity)}</span><b>{score.counts.get(severity, 0)}</b></div>'
        for severity in SEVERITY_LEVELS
    )
    skipped = "".join(f"<li>{_e(message)}</li>" for message in context.skipped) or "<li>None</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(TOOL_NAME)} report &middot; {_e(context.hostname)}</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #172033; background: #f4f6fa; }}
body {{ margin: 0; }} main {{ max-width: 1100px; margin: auto; padding: 2rem 1rem; }}
header, .panel, .finding {{ background: white; border: 1px solid #dce2ec; border-radius: 12px; }}
header {{ padding: 1.5rem; }} h1 {{ margin: 0 0 .5rem; }} h2 {{ margin-top: 2rem; }}
.score {{ font-size: 2rem; font-weight: 700; margin: 1rem 0; }} .stats {{ display: flex; flex-wrap: wrap; gap: .6rem; }}
.stat {{ min-width: 100px; padding: .8rem; border-radius: 8px; background: #edf1f7; }}
.stat span, .stat b {{ display: block; }} .stat b {{ font-size: 1.4rem; margin-top: .2rem; }}
.filters {{ display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0; }}
.filters button, .copy-fix {{ border: 0; border-radius: 6px; padding: .55rem .8rem; cursor: pointer; background: #dce5f5; }}
.finding {{ margin: .7rem 0; overflow: hidden; }} .finding-header {{ width: 100%; display: flex; gap: .7rem; align-items: center; text-align: left; border: 0; background: white; padding: 1rem; cursor: pointer; }}
.target {{ margin-left: auto; color: #52627a; overflow-wrap: anywhere; }} .finding-details {{ padding: 0 1rem 1rem; border-top: 1px solid #e7ebf2; }}
.badge {{ color: white; border-radius: 5px; padding: .2rem .4rem; font-size: .75rem; }} .critical {{ background: #b42318; }} .high {{ background: #c2410c; }} .medium {{ background: #a16207; }} .low {{ background: #2563eb; }} .info {{ background: #64748b; }}
.fix {{ display: flex; gap: .8rem; align-items: center; background: #f4f6fa; padding: .7rem; }} code {{ overflow-wrap: anywhere; }}
.panel {{ padding: 1rem; margin-top: 1rem; }} footer {{ color: #52627a; margin-top: 2rem; font-size: .9rem; }}
@media print {{ .filters, .copy-fix {{ display: none; }} body {{ background: white; }} }}
</style>
</head>
<body><main>
<header>
  <h1>{_e(TOOL_NAME)} &mdash; Linux Privilege &amp; Permission Risk Analyzer</h1>
  <p>Host: {_e(context.hostname)} &middot; Kernel: {_e(context.kernel)} &middot; Run as: {_e(context.run_as_user)} &middot; Time: {_e(context.scan_time)}</p>
  <div class="score">Risk score: {_e(score.value)} / 100 &middot; Grade {_e(score.grade)}</div>
  <div class="stats">{severity_cards}</div>
</header>
<section class="panel">
  <h2>Findings</h2>
  <div class="filters">
    <button type="button" data-filter="ALL">All</button>
    {"".join(f'<button type="button" data-filter="{_e(severity)}">{_e(severity.title())}</button>' for severity in SEVERITY_LEVELS)}
  </div>
  <div id="findings">{cards or "<p>No findings.</p>"}</div>
</section>
<section class="panel"><h2>Skipped checks</h2><ul>{skipped}</ul></section>
<footer>AccessLens {VERSION}. Read-only audit. Fix commands are suggestions &mdash; review before running.</footer>
</main>
<script>
const findings = [...document.querySelectorAll('.finding')];
document.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => {{
  const filter = button.dataset.filter;
  findings.forEach(card => {{ card.hidden = filter !== 'ALL' && card.dataset.severity !== filter; }});
}}));
document.querySelectorAll('.finding-header').forEach(button => button.addEventListener('click', () => {{
  const details = button.nextElementSibling;
  const open = !details.hidden; details.hidden = open; button.setAttribute('aria-expanded', String(!open));
}}));
document.querySelectorAll('.copy-fix').forEach(button => button.addEventListener('click', async () => {{
  await navigator.clipboard.writeText(JSON.parse(button.dataset.fix));
  button.textContent = 'Copied';
}}));
</script>
</body></html>
"""


def save(
    path: str | Path,
    context: ScanContext,
    findings: list[Finding],
    score: ScoreResult,
) -> None:
    """Write a self-contained HTML report."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(context, findings, score), encoding="utf-8")
