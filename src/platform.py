"""Platform abstraction layer for cross-platform compatibility.

Handles: executable names, path rules, file permissions, process lifecycle,
CPU architecture detection, download format selection, temp directories.

sing-box version target: v1.13.14
Asset naming pattern: sing-box-{version}-{os}-{arch}.{ext}
- Windows: .zip
- Linux/macOS: .tar.gz
"""

import os
import sys
import platform
import subprocess
import logging
import tempfile
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def _system() -> str:
    """Return canonical OS name matching sing-box release convention."""
    if sys.platform == "win32":
        return "windows"
    elif sys.platform == "darwin":
        return "darwin"
    else:
        return "linux"


def get_executable_name() -> str:
    """Return sing-box executable name for current platform."""
    if sys.platform == "win32":
        return "sing-box.exe"
    return "sing-box"


def get_archive_extension() -> str:
    """Return the archive extension for the current platform."""
    if sys.platform == "win32":
        return "zip"
    return "tar.gz"


def normalize_machine(arch: str) -> str:
    """Normalize CPU architecture to sing-box release naming."""
    mapping = {
        "x86_64": "amd64",
        "AMD64": "amd64",
        "i386": "386",
        "i686": "386",
        "x86": "386",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
        "armv6l": "armv6",
        "armv5l": "armv5",
    }
    return mapping.get(arch, arch)


def detect_platform_info() -> dict:
    """Detect current platform information for sing-box download.

    Returns:
        dict with keys: system, arch, executable_name, archive_ext
    """
    system = _system()
    arch = normalize_machine(platform.machine())
    return {
        "system": system,
        "arch": arch,
        "executable_name": get_executable_name(),
        "archive_ext": get_archive_extension(),
        "python_os": sys.platform,
        "platform_release": platform.release(),
    }


def get_release_asset_name(version: str) -> str:
    """Generate the expected release asset filename for the current platform.

    Based on sing-box v1.13.x release naming convention.
    """
    info = detect_platform_info()
    return f"sing-box-{version}-{info['system']}-{info['arch']}.{info['archive_ext']}"


def resolve_executable_path(path_str: str) -> Path | None:
    """Resolve an executable path, searching PATH if needed."""
    if not path_str:
        return None

    p = Path(path_str)
    if p.is_file():
        return p.resolve()

    exe_name = get_executable_name()
    if not p.suffix and sys.platform == "win32":
        p = p.with_suffix(".exe")

    if p.is_file():
        return p.resolve()

    which = shutil.which(str(p))
    if not which and shutil.which(exe_name):
        which = shutil.which(exe_name)

    return Path(which) if which else None


def get_temp_dir() -> Path:
    """Get a temporary directory for downloads and intermediate files."""
    tmp = Path(tempfile.gettempdir()) / "singharbor"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def run_command(cmd: list[str], timeout: int = 30,
                capture_output: bool = True,
                cwd: Path | None = None,
                env: dict | None = None) -> subprocess.CompletedProcess:
    """Run an external command with timeout and safe argument handling.

    All commands must be passed as a list to prevent shell injection.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        return result
    except subprocess.TimeoutExpired as e:
        logger.error("Command timed out after %ds: %s", timeout, cmd)
        raise
    except FileNotFoundError:
        logger.error("Executable not found: %s", cmd[0])
        raise
    except Exception as e:
        logger.error("Command failed: %s - %s", cmd, e)
        raise


def check_capabilities() -> dict:
    """Check capabilities and limitations of the current platform.

    Returns a dict describing what operations may need elevated privileges.
    """
    caps = {
        "is_admin": _is_admin(),
        "can_bind_privileged_ports": False,
        "can_modify_firewall": False,
        "notes": [],
    }

    if sys.platform == "win32":
        caps["can_modify_firewall"] = caps["is_admin"]
        if caps["is_admin"]:
            caps["notes"].append("Running as Administrator on Windows")
        else:
            caps["notes"].append(
                "Not running as Administrator - "
                "privileged ports (<1024) and firewall changes require admin"
            )
    elif sys.platform == "darwin":
        caps["can_bind_privileged_ports"] = False
        caps["notes"].append(
            "Binding to ports <1024 requires root on macOS. "
            "Use a higher port instead."
        )
    elif sys.platform.startswith("linux"):
        caps["can_bind_privileged_ports"] = (os.geteuid() == 0)
        if os.geteuid() != 0:
            caps["notes"].append(
                "Not running as root. Ports <1024 require CAP_NET_BIND_SERVICE "
                "or root. Use a higher port or grant capability."
            )

    return caps


def _is_admin() -> bool:
    """Check if the current process has admin/root privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False
