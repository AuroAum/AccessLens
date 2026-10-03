"""Small shared helpers for permissions, paths, and safe display values."""

import shlex
import stat


def mode_to_string(mode: int) -> str:
    """Return a familiar ``rwx`` permission string for a file mode."""

    return stat.filemode(mode)


def mode_to_octal(mode: int) -> str:
    """Return the permission bits as a four-digit octal string."""

    return format(stat.S_IMODE(mode), "04o")


def quote_path(path: str) -> str:
    """Quote a path for a suggested shell command without executing it."""

    return shlex.quote(path)


def is_world_writable(mode: int) -> bool:
    """Report whether the mode grants write permission to other users."""

    return bool(mode & stat.S_IWOTH)
