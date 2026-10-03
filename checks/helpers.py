"""Shared constructors and small predicates used by check modules."""

from ..models import Finding


def finding(
    check_id: str,
    title: str,
    category: str,
    severity: str,
    target: str,
    description: str,
    why_risky: str,
    fix_command: str,
    evidence: str,
) -> Finding:
    """Create a finding with the project's consistent field order."""

    return Finding(
        check_id,
        title,
        category,
        severity,
        target,
        description,
        why_risky,
        fix_command,
        evidence,
    )
