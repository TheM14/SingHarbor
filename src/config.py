"""Application configuration management.

sing-box version target: v1.13.14
Reference: https://sing-box.sagernet.org/configuration/
"""

import os
import logging
import json
from pathlib import Path
from .utils import json_save_atomic

logger = logging.getLogger(__name__)


class AppConfig:
    """SingHarbor configuration loaded from file or defaults."""

    def __init__(self, config_path: Path | None = None,
                 project_root: Path | None = None):
        self.config_path = config_path
        self._project_root = project_root or Path.cwd()
        self._data: dict = {}
        self.load()

    @property
    def data_dir(self) -> Path:
        """All project data stays inside the project directory for portability."""
        return self._project_root / "data"

    @property
    def config_file_path(self) -> Path:
        return self.data_dir / "settings.json"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "singharbor.db"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def kernels_dir(self) -> Path:
        return self._project_root / "kernels"

    @property
    def downloads_dir(self) -> Path:
        return self._project_root / "downloads"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def listen_host(self) -> str:
        return self._data.get("listen_host", "127.0.0.1")

    @property
    def listen_port(self) -> int:
        try:
            return int(self._data.get("listen_port", 51080))
        except (ValueError, TypeError):
            return 51080

    @property
    def session_duration_minutes(self) -> int:
        try:
            return int(self._data.get("session_duration_minutes", 60))
        except (ValueError, TypeError):
            return 60

    @property
    def login_max_attempts(self) -> int:
        try:
            return int(self._data.get("login_max_attempts", 5))
        except (ValueError, TypeError):
            return 5

    @property
    def login_lockout_minutes(self) -> int:
        try:
            return int(self._data.get("login_lockout_minutes", 15))
        except (ValueError, TypeError):
            return 15

    @property
    def secret_key(self) -> str:
        key = self._data.get("secret_key", "")
        if not key:
            import secrets
            key = secrets.token_hex(32)
            self._data["secret_key"] = key
            self.save()
        return key

    @property
    def public_endpoints(self) -> dict:
        """Normalized public client endpoint preferences."""
        from .endpoints import build_endpoint_profile
        profile, _ = build_endpoint_profile(self._data.get("public_endpoints", {}))
        return profile

    @property
    def cloudflare_zone_id(self) -> str:
        return str(self._data.get("cloudflare_zone_id", "")).strip()

    @property
    def inbound_endpoint_profiles(self) -> dict[str, dict]:
        """Per-inbound endpoint profiles used by split direct/CDN deployments."""
        from .endpoints import build_endpoint_profile
        stored = self._data.get("inbound_endpoint_profiles", {})
        if not isinstance(stored, dict):
            return {}
        result = {}
        for tag, values in stored.items():
            if isinstance(values, dict):
                result[str(tag)] = build_endpoint_profile(values)[0]
        return result

    def load(self):
        path = self.config_path or self.config_file_path
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                logger.warning("Failed to load config, using defaults")
                self._data = {}
        else:
            self._data = {}

    def save(self):
        path = self.config_path or self.config_file_path
        json_save_atomic(self._data, path)

    def update(self, key: str, value):
        self._data[key] = value
        self.save()

    def update_many(self, values: dict):
        self._data.update(values)
        self.save()

    def set_public_endpoints(self, profile: dict, cloudflare_zone_id: str = ""):
        self.update_many({
            "public_endpoints": dict(profile),
            "cloudflare_zone_id": str(cloudflare_zone_id or "").strip(),
        })

    def set_inbound_endpoint_profiles(self, profiles: dict[str, dict]):
        stored = dict(self._data.get("inbound_endpoint_profiles", {}))
        stored.update({str(tag): dict(profile) for tag, profile in profiles.items()})
        self.update("inbound_endpoint_profiles", stored)

    def remove_inbound_endpoint_profile(self, tag: str):
        stored = dict(self._data.get("inbound_endpoint_profiles", {}))
        if stored.pop(str(tag), None) is not None:
            self.update("inbound_endpoint_profiles", stored)

    def ensure_dirs(self):
        for d in [self.data_dir, self.log_dir, self.backup_dir,
                   self.downloads_dir, self.kernels_dir]:
            d.mkdir(parents=True, exist_ok=True)
