"""sing-box kernel management: detection, version query, downloads, version switching.

sing-box CLI commands:
  sing-box version   - Print version
  sing-box check     - Check configuration
  sing-box run       - Run with configuration
  sing-box format    - Format configuration
  sing-box generate  - Generate various things (rand, uuid, etc.)

Release download URL pattern:
  https://github.com/SagerNet/sing-box/releases/download/v{version}/{asset_name}
"""

import re
import logging
import tempfile
import shutil
import requests
import zipfile
import tarfile
from pathlib import Path
from dataclasses import dataclass
from .platform import (
    run_command, get_executable_name, get_release_asset_name,
    detect_platform_info, get_temp_dir,
)
from .sandbox import validate_executable_path

logger = logging.getLogger(__name__)

GITHUB_API_RELEASES = "https://api.github.com/repos/SagerNet/sing-box/releases"
GITHUB_DOWNLOAD = "https://github.com/SagerNet/sing-box/releases/download"

VERSION_RE = re.compile(r"sing-box version (\S+)")


@dataclass
class KernelInfo:
    """Information about a sing-box kernel installation."""
    path: Path
    version: str
    is_active: bool = False


class KernelManager:
    """Manages sing-box kernel executables."""

    def __init__(self, kernels_dir: Path):
        self.kernels_dir = Path(kernels_dir)
        self.kernels_dir.mkdir(parents=True, exist_ok=True)

    def detect_kernel(self, search_paths: list[str] | None = None) -> KernelInfo | None:
        """Detect an installed sing-box executable."""
        from .platform import resolve_executable_path

        candidates = []
        if search_paths:
            candidates.extend(search_paths)

        for p in self.kernels_dir.iterdir():
            if p.name in ("sing-box", "sing-box.exe") or p.name.startswith("sing-box-"):
                candidates.append(str(p))

        for candidate in candidates:
            path = resolve_executable_path(candidate)
            if path:
                version = self.get_version(path)
                if version:
                    return KernelInfo(path=path, version=version)
        return None

    def get_version(self, kernel_path: Path) -> str | None:
        """Query the version of a sing-box executable."""
        validate_executable_path(kernel_path)
        try:
            result = run_command([str(kernel_path), "version"], timeout=10)
            if result.returncode == 0:
                match = VERSION_RE.search(result.stdout)
                if match:
                    return match.group(1)
            logger.warning("Failed to get version from %s: %s",
                           kernel_path, result.stderr)
            return None
        except Exception as e:
            logger.error("Error querying version from %s: %s", kernel_path, e)
            return None

    def check_config(self, kernel_path: Path, config_path: Path) -> tuple[bool, str]:
        """Validate a configuration file using sing-box check.

        Returns (success, message).
        """
        validate_executable_path(kernel_path)
        try:
            result = run_command(
                [str(kernel_path), "check", "-c", str(config_path)],
                timeout=30
            )
            if result.returncode == 0:
                return True, "Configuration is valid"
            return False, result.stderr.strip() or "Configuration check failed"
        except Exception as e:
            return False, str(e)

    def format_config(self, kernel_path: Path, config_path: Path) -> tuple[bool, str]:
        """Format a configuration file using sing-box format."""
        validate_executable_path(kernel_path)
        try:
            result = run_command(
                [str(kernel_path), "format", "-c", str(config_path), "-w"],
                timeout=30
            )
            if result.returncode == 0:
                return True, "Configuration formatted"
            return False, result.stderr.strip() or "Format failed"
        except Exception as e:
            return False, str(e)

    def list_local_versions(self) -> list[KernelInfo]:
        """List all locally installed kernel versions."""
        versions = []
        for p in self.kernels_dir.iterdir():
            if p.is_file() and (p.name.startswith("sing-box") or
                                p.name in ("sing-box", "sing-box.exe")):
                version = self.get_version(p)
                if version:
                    versions.append(KernelInfo(path=p, version=version))
        return versions

    def get_installed_path(self, version: str) -> Path:
        """Get the path where a specific version should be/is installed."""
        exe_name = get_executable_name()
        return self.kernels_dir / f"sing-box-{version}" / exe_name

    def download_version(self, version: str) -> Path:
        """Download a specific version of sing-box for the current platform.

        Returns the path to the extracted executable.

        Raises: Exception on download/extraction failure.
        """
        asset_name = get_release_asset_name(version)
        download_url = f"{GITHUB_DOWNLOAD}/v{version}/{asset_name}"

        logger.info("Downloading sing-box %s from %s", version, download_url)

        tmp_dir = get_temp_dir()
        archive_path = tmp_dir / asset_name

        response = requests.get(download_url, stream=True, timeout=300)
        response.raise_for_status()

        with open(archive_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        extract_dir = tmp_dir / f"sing-box-{version}"
        extract_dir.mkdir(exist_ok=True)

        self._extract_archive(archive_path, extract_dir)

        exe_name = get_executable_name()
        exe_path = None
        for p in extract_dir.rglob(exe_name):
            exe_path = p
            break

        if not exe_path:
            raise FileNotFoundError(
                f"sing-box executable not found in archive: {asset_name}"
            )

        dest_dir = self.kernels_dir / f"sing-box-{version}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / exe_name
        shutil.copy2(exe_path, dest_path)

        if not self._check_download(dest_path, version):
            dest_path.unlink(missing_ok=True)
            raise ValueError("Downloaded binary version mismatch")

        archive_path.unlink(missing_ok=True)
        shutil.rmtree(extract_dir, ignore_errors=True)

        return dest_path

    def _extract_archive(self, archive_path: Path, dest_dir: Path):
        """Extract zip or tar.gz archive."""
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest_dir)
        elif archive_path.suffix in (".gz", ".tgz") or ".tar." in archive_path.name:
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(dest_dir)
        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")

    def _check_download(self, kernel_path: Path, expected_version: str) -> bool:
        """Verify the downloaded binary reports the correct version."""
        actual = self.get_version(kernel_path)
        if actual != expected_version:
            logger.error("Version mismatch: expected %s, got %s", expected_version, actual)
            return False
        return True

    def fetch_releases(self, include_prerelease: bool = False) -> list[dict]:
        """Fetch available releases from GitHub API."""
        try:
            response = requests.get(GITHUB_API_RELEASES, timeout=30,
                                    params={"per_page": 20})
            response.raise_for_status()
            releases = response.json()
            result = []
            for rel in releases:
                if rel.get("draft"):
                    continue
                if rel.get("prerelease") and not include_prerelease:
                    continue
                version = rel.get("tag_name", "").lstrip("v")
                result.append({
                    "version": version,
                    "tag": rel.get("tag_name", ""),
                    "url": rel.get("html_url", ""),
                    "prerelease": rel.get("prerelease", False),
                    "published_at": rel.get("published_at", ""),
                })
            return result
        except Exception as e:
            logger.error("Failed to fetch releases: %s", e)
            return []

    def check_update(self, current_version: str,
                     include_prerelease: bool = False) -> dict | None:
        """Check if a newer stable version is available."""
        releases = self.fetch_releases(include_prerelease)
        current = _parse_version(current_version)
        latest = None
        for rel in releases:
            ver = _parse_version(rel["version"])
            if ver > current:
                if latest is None or ver > _parse_version(latest["version"]):
                    latest = rel
        return latest


def _parse_version(v: str) -> tuple:
    """Parse version string into comparable tuple."""
    parts = re.split(r"[-.]", v)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append((0, p))
    return tuple(result)
