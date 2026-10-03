"""Evaluate passwd, shadow, and group records for identity risks."""

from collections import defaultdict

from ..config import ADMIN_GROUP_NAMES, NON_INTERACTIVE_SHELL_NAMES
from ..models import Finding, ScanContext
from ..utils import quote_path
from .helpers import finding


def run(context: ScanContext) -> list[Finding]:
    """Return findings for user accounts and administrative groups."""

    findings: list[Finding] = []

    for user in context.users:
        if user.uid == 0 and user.name != "root":
            findings.append(
                finding(
                    "USR-001",
                    "Non-root account with UID 0",
                    "Users",
                    "CRITICAL",
                    user.name,
                    f"Account {user.name!r} has UID 0.",
                    "UID 0 has root's full authority, so this account is another path to complete system control.",
                    f"sudo usermod -u <new_uid> {quote_path(user.name)}",
                    f"name={user.name} uid=0",
                )
            )

        shell_name = user.shell.rsplit("/", 1)[-1]
        if user.uid < 1000 and user.uid != 0 and shell_name not in NON_INTERACTIVE_SHELL_NAMES:
            findings.append(
                finding(
                    "USR-004",
                    "System account with an interactive login shell",
                    "Users",
                    "MEDIUM",
                    user.name,
                    f"System account {user.name!r} uses {user.shell}.",
                    "Service accounts normally do not need interactive logins; an attacker may use one as a foothold.",
                    f"sudo usermod -s /usr/sbin/nologin {quote_path(user.name)}",
                    f"uid={user.uid} shell={user.shell}",
                )
            )

    if context.shadow is not None:
        for record in context.shadow:
            if record.password_field == "":
                findings.append(
                    finding(
                        "USR-002",
                        "Account with empty password",
                        "Users",
                        "CRITICAL",
                        record.name,
                        f"Account {record.name!r} has an empty password field.",
                        "Anyone who can authenticate as this account may log in without knowing a password.",
                        f"sudo passwd -l {quote_path(record.name)}",
                        f"name={record.name} password_field=empty",
                    )
                )

    uid_users: dict[int, list[str]] = defaultdict(list)
    for user in context.users:
        uid_users[user.uid].append(user.name)
    for uid, names in uid_users.items():
        if len(names) > 1:
            target = ", ".join(names)
            findings.append(
                finding(
                    "USR-003",
                    "Duplicate UIDs",
                    "Users",
                    "HIGH",
                    target,
                    f"Multiple accounts share UID {uid}.",
                    "Accounts with the same UID share file ownership and effective identity.",
                    "Review the accounts and assign each one a unique UID.",
                    f"uid={uid} names={target}",
                )
            )

    for group in context.groups:
        if group.name in ADMIN_GROUP_NAMES and group.members:
            findings.append(
                finding(
                    "GRP-001",
                    "Members of an administrative group",
                    "Groups",
                    "INFO",
                    group.name,
                    f"Administrative group {group.name!r} has members.",
                    "These accounts may have elevated privileges and should be reviewed against the intended access policy.",
                    "Review group membership and remove accounts that do not need administrative access.",
                    f"group={group.name} members={','.join(group.members)}",
                )
            )

    return findings
