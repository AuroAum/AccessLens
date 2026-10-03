"""Read sudoers rules and included sudoers.d files without invoking sudo.

The parser deliberately treats sudoers as text. It does not attempt to
evaluate every detail of sudoers syntax; later check modules inspect the raw
rule text using explicit, testable policies.
"""

from pathlib import Path

try:
    from ..models import SudoRule
except ImportError:
    from models import SudoRule


def _note(skipped: list[str] | None, message: str) -> None:
    """Add a non-fatal sudoers collection problem to the skipped list."""

    if skipped is not None:
        skipped.append(message)


def _parse_file(path: Path, skipped: list[str] | None) -> list[SudoRule] | None:
    """Parse meaningful rule lines from one sudoers file."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, PermissionError, IsADirectoryError) as error:
        _note(skipped, f"Skipped {path}: {error.strerror or 'file cannot be read'}")
        return None
    except UnicodeError as error:
        _note(skipped, f"Skipped {path}: invalid text encoding ({error})")
        return None

    rules: list[SudoRule] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("Defaults"):
            continue
        rules.append(SudoRule(str(path), line_number, stripped))
    return rules


def parse_sudoers(
    path: str = "/etc/sudoers",
    directory: str = "/etc/sudoers.d",
    skipped: list[str] | None = None,
) -> list[SudoRule] | None:
    """Read the main sudoers file and regular files in its include directory."""

    main_rules = _parse_file(Path(path), skipped)
    if main_rules is None:
        return None

    rules = list(main_rules)
    include_dir = Path(directory)
    try:
        entries = sorted(include_dir.iterdir())
    except (FileNotFoundError, PermissionError, NotADirectoryError) as error:
        _note(skipped, f"Skipped {include_dir}: {error.strerror or 'directory cannot be read'}")
        return rules

    for entry in entries:
        if not entry.is_file():
            continue
        parsed = _parse_file(entry, skipped)
        if parsed is not None:
            rules.extend(parsed)
    return rules
