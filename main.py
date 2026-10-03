"""AccessLens command-line entry point.

Phase 6 runs the read-only collection and check pipeline and renders the
terminal report. JSON and HTML report writing are added in later phases.
"""

import argparse
from datetime import datetime
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from .config import QUICK_SCAN_PATHS, TOOL_NAME, VERSION
    from .collectors import build_context
    from .collectors.filesystem import collect_filesystem, collect_sensitive_files
    from .checks import ALL_CHECKS
    from .reporters.terminal import render
    from .reporters.json_report import save as save_json
    from .reporters.html_report import save as save_html
    from .compare import compare_files
    from .reporters.compare_terminal import render as render_comparison
    from .scoring import calculate_score
except ImportError:
    from accesslens.config import QUICK_SCAN_PATHS, TOOL_NAME, VERSION
    from accesslens.collectors import build_context
    from accesslens.collectors.filesystem import collect_filesystem, collect_sensitive_files
    from accesslens.checks import ALL_CHECKS
    from accesslens.reporters.terminal import render
    from accesslens.reporters.json_report import save as save_json
    from accesslens.reporters.html_report import save as save_html
    from accesslens.compare import compare_files
    from accesslens.reporters.compare_terminal import render as render_comparison
    from accesslens.scoring import calculate_score


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level parser and its future subcommands."""

    parser = argparse.ArgumentParser(
        prog="accesslens",
        description="Read-only Linux privilege and permission risk analyzer.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan the local Linux system")
    scan_parser.add_argument(
        "--paths",
        nargs="+",
        metavar="PATH",
        help="directories to scan instead of the configured defaults",
    )
    debug_parser = subparsers.add_parser(
        "debug-collectors",
        help="print parsed users, groups, shadow status, and sudo rules",
    )
    debug_parser.add_argument("--passwd", default="/etc/passwd")
    debug_parser.add_argument("--group", default="/etc/group")
    debug_parser.add_argument("--shadow", default="/etc/shadow")
    debug_parser.add_argument("--sudoers", default="/etc/sudoers")
    debug_parser.add_argument("--sudoers-dir", default="/etc/sudoers.d")
    scan_parser.add_argument(
        "--quick",
        action="store_true",
        help=f"scan only the quick-demo paths: {', '.join(QUICK_SCAN_PATHS)}",
    )
    scan_parser.add_argument(
        "--output-dir",
        default="./reports",
        help="directory for generated reports (default: ./reports)",
    )
    scan_parser.add_argument(
        "--format",
        default="terminal,html,json",
        help="comma-separated report formats (default: terminal,html,json)",
    )
    scan_parser.add_argument("--no-color", action="store_true", help="disable terminal colors")
    scan_parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info"),
        help="return exit code 1 for findings at or above this severity",
    )

    compare_parser = subparsers.add_parser(
        "compare", help="compare two JSON scan reports"
    )
    compare_parser.add_argument("before", help="path to the earlier JSON report")
    compare_parser.add_argument("after", help="path to the later JSON report")
    compare_parser.add_argument("--output-dir", default="./reports")
    return parser


def run_scan(args: argparse.Namespace) -> int:
    """Collect facts, run every registered check, and render the terminal report."""

    paths = QUICK_SCAN_PATHS if args.quick else (args.paths or None)
    try:
        context = build_context(scan_paths=paths)
        collect_filesystem(context, scan_paths=context.scan_paths)
        collect_sensitive_files(context)
        findings = [finding for check in ALL_CHECKS for finding in check(context)]
        score = calculate_score(findings)
        requested_formats = {
            value.strip().lower()
            for value in args.format.split(",")
            if value.strip()
        }
        if "terminal" in requested_formats:
            render(context, findings, score, no_color=args.no_color)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = f"accesslens_{context.hostname}_{timestamp}"
        output_dir = Path(args.output_dir)
        if "json" in requested_formats:
            save_json(output_dir / f"{stem}.json", context, findings, score)
            print(f"JSON report saved to {output_dir / f'{stem}.json'}")
        if "html" in requested_formats:
            save_html(output_dir / f"{stem}.html", context, findings, score)
            print(f"HTML report saved to {output_dir / f'{stem}.html'}")
    except KeyboardInterrupt:
        print("scan cancelled", file=sys.stderr)
        return 130
    except OSError as error:
        print(f"{TOOL_NAME}: scan error: {error}", file=sys.stderr)
        return 2

    deferred = requested_formats - {"terminal", "json", "html"}
    if deferred:
        print(
            f"{TOOL_NAME}: report formats not implemented yet: {', '.join(sorted(deferred))}",
            file=sys.stderr,
        )

    if args.fail_on:
        threshold = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").index(args.fail_on.upper())
        if any(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").index(item.severity) <= threshold for item in findings):
            return 1
    return 0


def run_debug_collectors(args: argparse.Namespace) -> int:
    """Print the Phase 2 collection result in a human-readable form."""

    context = build_context(
        passwd_path=args.passwd,
        group_path=args.group,
        shadow_path=args.shadow,
        sudoers_path=args.sudoers,
        sudoers_dir=args.sudoers_dir,
    )
    print(f"Users: {len(context.users)}")
    for user in context.users:
        print(f"  {user.name}: uid={user.uid} gid={user.gid} shell={user.shell}")
    print(f"Groups: {len(context.groups)}")
    for group in context.groups:
        members = ", ".join(group.members) or "(none)"
        print(f"  {group.name}: gid={group.gid} members={members}")
    if context.shadow is None:
        print("Shadow: skipped")
    else:
        print(f"Shadow records: {len(context.shadow)}")
    if context.sudo_rules is None:
        print("Sudo rules: skipped")
    else:
        print(f"Sudo rules: {len(context.sudo_rules)}")
        for rule in context.sudo_rules:
            print(f"  {rule.source_file}:{rule.line_number}: {rule.raw_text}")
    if context.skipped:
        print("Skipped:")
        for message in context.skipped:
            print(f"  - {message}")
    return 0


def run_compare(args: argparse.Namespace) -> int:
    """Load two JSON reports and print NEW, RESOLVED, and UNCHANGED findings."""

    try:
        comparison = compare_files(args.before, args.after)
        render_comparison(comparison)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"{TOOL_NAME}: compare error: {error}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse command-line arguments and dispatch the selected command."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "compare":
        return run_compare(args)
    if args.command == "debug-collectors":
        return run_debug_collectors(args)
    parser.error("a command is required")
    return 2


if __name__ == "__main__":
    sys.exit(main())
