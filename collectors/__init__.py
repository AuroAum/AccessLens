"""Build a scan context by running the read-only system collectors."""

from datetime import datetime, timezone
import getpass
import os
import platform

try:
    from ..config import DEFAULT_SCAN_PATHS
    from ..models import ScanContext
    from .sudoers import parse_sudoers
    from .users import parse_group, parse_passwd, parse_shadow
    from .cron import collect_cron
    from .ssh_keys import collect_ssh_files
except ImportError:
    from config import DEFAULT_SCAN_PATHS
    from models import ScanContext
    from collectors.sudoers import parse_sudoers
    from collectors.users import parse_group, parse_passwd, parse_shadow
    from collectors.cron import collect_cron
    from collectors.ssh_keys import collect_ssh_files


def build_context(
    scan_paths: list[str] | None = None,
    passwd_path: str = "/etc/passwd",
    group_path: str = "/etc/group",
    shadow_path: str = "/etc/shadow",
    sudoers_path: str = "/etc/sudoers",
    sudoers_dir: str = "/etc/sudoers.d",
    etc_dir: str = "/etc",
    root_home: str = "/root",
    home_base: str = "/home",
) -> ScanContext:
    """Collect identity and sudo facts into one context.

    A missing or unreadable privileged file is recorded in ``skipped`` while
    the other collectors continue, which makes normal-user scans useful.
    """

    skipped: list[str] = []
    users = parse_passwd(passwd_path, skipped) or []
    groups = parse_group(group_path, skipped) or []
    shadow = parse_shadow(shadow_path, skipped)
    sudo_rules = parse_sudoers(sudoers_path, sudoers_dir, skipped)
    context = ScanContext(
        hostname=platform.node(),
        kernel=platform.release(),
        scan_time=datetime.now(timezone.utc).isoformat(),
        run_as_user=getpass.getuser(),
        is_root=(os.geteuid() == 0),
        scan_paths=list(scan_paths or DEFAULT_SCAN_PATHS),
        users=users,
        groups=groups,
        shadow=shadow,
        sudo_rules=sudo_rules,
        skipped=skipped,
    )
    collect_cron(context, etc_dir=etc_dir)
    collect_ssh_files(context, root_home=root_home, home_base=home_base)
    return context
