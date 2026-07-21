"""Security sandbox for path restrictions and command safety.

Prevents:
- Arbitrary file reads/writes outside allowed paths
- Directory traversal attacks
- Symlink-based path escapes
- Command injection through crafted paths
"""

import os
from pathlib import Path

ALLOWED_DIRS: list[Path] = []


def set_allowed_dirs(*dirs: Path):
    """Configure the set of directories where file operations are permitted."""
    global ALLOWED_DIRS
    ALLOWED_DIRS = [d.resolve() for d in dirs]


def sanitize_path(path_str: str, base_dir: Path | None = None) -> Path:
    """Sanitize and validate a path.

    Ensures the resolved path stays within allowed directories.
    Raises ValueError if path escapes allowed boundaries.
    """
    if not path_str:
        raise ValueError("Empty path not allowed")

    p = Path(path_str)
    if base_dir:
        p = base_dir / p

    try:
        resolved = p.resolve()
    except (OSError, ValueError):
        raise ValueError(f"Invalid path: {path_str}")

    if ALLOWED_DIRS:
        for allowed in ALLOWED_DIRS:
            try:
                resolved.relative_to(allowed)
                return resolved
            except ValueError:
                continue
        raise ValueError(f"Path outside allowed directories: {path_str}")

    return resolved


def is_path_safe(path: Path) -> bool:
    """Check if a path is within allowed directories."""
    if not ALLOWED_DIRS:
        return True
    try:
        resolved = path.resolve()
    except (OSError, ValueError):
        return False
    for allowed in ALLOWED_DIRS:
        try:
            resolved.relative_to(allowed)
            return True
        except ValueError:
            continue
    return False


def ensure_parent(path: Path):
    """Ensure the parent directory of a path exists."""
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    if not is_path_safe(parent):
        raise ValueError(f"Path outside allowed directories: {parent}")


def validate_executable_path(path: Path) -> Path:
    """Validate that an executable path is safe and exists.

    The executable must be in an allowed directory or a well-known system path.
    """
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Executable not found: {path}")

    if ALLOWED_DIRS:
        for allowed in ALLOWED_DIRS:
            try:
                resolved.relative_to(allowed)
                return resolved
            except ValueError:
                continue

    from .platform import shutil
    if shutil.which(path.name):
        resolved_sys = Path(shutil.which(path.name))
        if resolved_sys and resolved.samefile(resolved_sys):
            return resolved

    raise ValueError(f"Executable outside allowed directories: {path}")
