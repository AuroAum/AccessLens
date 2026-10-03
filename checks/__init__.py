"""Registry for the checks currently implemented by AccessLens."""

from .cron_check import run as run_cron_checks
from .file_check import run as run_file_checks
from .sudo_check import run as run_sudo_checks
from .suid_check import run as run_suid_checks
from .users_check import run as run_user_checks

ALL_CHECKS = [
    run_user_checks,
    run_sudo_checks,
    run_file_checks,
    run_suid_checks,
    run_cron_checks,
]
