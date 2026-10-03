"""Central configuration for AccessLens.

This module keeps policy decisions in one place so the collectors and checks
can share the same defaults without duplicating security-sensitive constants.
"""

from pathlib import Path

TOOL_NAME = "AccessLens"
VERSION = "1.0.0"

SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}
SEVERITY_CAPS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}

DEFAULT_SCAN_PATHS = [
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/opt",
    "/home",
    "/var",
    "/srv",
    "/root",
]
QUICK_SCAN_PATHS = ["/etc", "/home", "/opt", "/usr/local"]
SKIP_DIRS = {
    Path("/proc"),
    Path("/sys"),
    Path("/dev"),
    Path("/run"),
    Path("/snap"),
    Path("/var/lib/docker"),
    Path("/var/lib/lxcfs"),
}

SENSITIVE_PATHS = (
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
)
ALLOWED_WORLD_WRITABLE_PATH_PREFIXES = ("/dev/shm", "/var/lock")
SYSTEM_PATH_PREFIXES = (
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
)
ADMIN_GROUP_NAMES = {"sudo", "wheel", "admin"}
NON_INTERACTIVE_SHELL_NAMES = {"nologin", "false", "sync", "shutdown", "halt"}
SSH_KEY_NAMES = {"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "authorized_keys"}
CRON_DIRECTORIES = (
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)
DANGEROUS_SUID = {
    "bash", "sh", "dash", "zsh", "find", "vim", "vi", "nano", "less",
    "more", "awk", "perl", "python", "python3", "ruby", "cp", "mv", "env",
    "nmap", "tar", "node",
}
SUID_BASELINE = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec",
    "/usr/bin/fusermount3",
    "/usr/bin/chage",
    "/usr/bin/expiry",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
}
SENSITIVE_FILE_POLICIES = {
    "/etc/passwd": (0o644, "HIGH"),
    "/etc/group": (0o644, "MEDIUM"),
    "/etc/shadow": (0o640, "CRITICAL"),
    "/etc/gshadow": (0o640, "HIGH"),
    "/etc/sudoers": (0o440, "HIGH"),
    "/etc/ssh/sshd_config": (0o644, "MEDIUM"),
    "/root": (0o700, "HIGH"),
}
