"""sing-box configuration management: read, check, backup, restore, atomic save.

sing-box version target: v1.13.14
Configuration format: JSON

Key operations:
- Read configuration (preserving unknown fields)
- Validate with sing-box check command
- Backup before modification
- Atomic save (write temp, validate, rename)
- Config history tracking
- Diff display
- Restore from backup
"""

import json
import shutil
import logging
from pathlib import Path
from datetime import datetime
from .utils import compute_hash, json_load_keep_unknown, json_save_atomic, generate_diff_dict
from .sandbox import sanitize_path, is_path_safe

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages sing-box configuration files."""

    def __init__(self, config_path: Path, backup_dir: Path,
                 kernel_manager=None):
        self.config_path = Path(config_path)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._kernel_manager = kernel_manager

    @property
    def exists(self) -> bool:
        return self.config_path.exists()

    def read(self) -> dict:
        """Read the current configuration, preserving all fields."""
        if not self.exists:
            return {
                "log": {"level": "info"},
                "inbounds": [],
                "outbounds": [
                    {"type": "direct", "tag": "direct"}
                ],
            }
        return json_load_keep_unknown(self.config_path)

    def get_inbounds(self) -> list[dict]:
        """Get all inbound configurations."""
        config = self.read()
        return config.get("inbounds", [])

    def set_config(self, config: dict, kernel_path: Path | None = None,
                   auto_backup: bool = True) -> tuple[bool, str]:
        """Save and validate a configuration atomically.

        1. Write candidate to temp file.
        2. Validate with sing-box check.
        3. Backup current config.
        4. Atomic replace.
        5. Return success/failure.

        Returns (success, message).
        """
        if auto_backup and self.exists:
            self.backup()

        tmp_path = self.config_path.parent / f".{self.config_path.name}.candidate"

        try:
            json_save_atomic(config, tmp_path)

            if kernel_path and self._kernel_manager:
                ok, msg = self._kernel_manager.check_config(kernel_path, tmp_path)
                if not ok:
                    tmp_path.unlink(missing_ok=True)
                    return False, f"Config validation failed: {msg}"

            tmp_path.replace(self.config_path)
            return True, "Configuration saved and validated"
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            return False, f"Failed to save config: {e}"

    def backup(self, description: str = "") -> str:
        """Create a timestamped backup of the current configuration.

        Returns the backup filename.
        """
        if not self.exists:
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        config_hash = compute_hash(self.config_path.read_text("utf-8"))[:12]
        backup_name = f"config_{timestamp}_{config_hash}.json"
        backup_path = self.backup_dir / backup_name

        shutil.copy2(self.config_path, backup_path)
        logger.info("Config backed up to %s", backup_name)
        return backup_name

    def list_backups(self) -> list[dict]:
        """List all available backups."""
        backups = []
        for p in sorted(self.backup_dir.glob("config_*.json"), reverse=True):
            stat = p.stat()
            backups.append({
                "filename": p.name,
                "path": str(p),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        return backups

    def restore(self, backup_name: str, kernel_path: Path | None = None) -> tuple[bool, str]:
        """Restore configuration from a backup.

        1. Backup current config first.
        2. Validate backup config with kernel.
        3. Restore.

        Returns (success, message).
        """
        sanitized = sanitize_path(backup_name, self.backup_dir)
        if not sanitized.exists():
            return False, f"Backup not found: {backup_name}"

        if self.exists:
            self.backup("before_restore")

        try:
            config = json_load_keep_unknown(sanitized)
            return self.set_config(config, kernel_path, auto_backup=False)
        except Exception as e:
            return False, f"Restore failed: {e}"

    def diff(self, other_config: dict) -> dict:
        """Compute diff between current config and another config."""
        current = self.read() if self.exists else {}
        return generate_diff_dict(current, other_config)

    def add_inbound(self, inbound: dict, kernel_path: Path | None = None,
                    auto_backup: bool = True) -> tuple[bool, str]:
        """Add a new inbound to the configuration.

        1. Load current config.
        2. Check for tag/port conflicts.
        3. Append inbound.
        4. Set config (validate + save + backup).
        """
        return self.add_inbounds(
            [inbound], kernel_path=kernel_path, auto_backup=auto_backup
        )

    def add_inbounds(self, new_inbounds: list[dict],
                     kernel_path: Path | None = None,
                     auto_backup: bool = True) -> tuple[bool, str]:
        """Atomically validate and add one or more inbound configurations."""
        if not new_inbounds:
            return False, "At least one inbound is required"

        config = self.read()
        existing_inbounds = config.get("inbounds", [])
        seen_tags = {item.get("tag", "") for item in existing_inbounds}
        seen_ports = {
            item.get("listen_port", 0): item.get("tag", "")
            for item in existing_inbounds if item.get("listen_port", 0)
        }

        for inbound in new_inbounds:
            tag = inbound.get("tag", "")
            port = inbound.get("listen_port", 0)
            if tag and tag in seen_tags:
                return False, f"Tag conflict: '{tag}' already exists"
            if port and port in seen_ports:
                return False, (
                    f"Port conflict: port {port} already used by "
                    f"'{seen_ports[port]}'"
                )
            if tag:
                seen_tags.add(tag)
            if port:
                seen_ports[port] = tag

        config.setdefault("inbounds", []).extend(new_inbounds)
        return self.set_config(config, kernel_path, auto_backup=auto_backup)

    def remove_inbound(self, tag: str, kernel_path: Path | None = None,
                       auto_backup: bool = True) -> tuple[bool, str]:
        """Remove an inbound by tag."""
        config = self.read()
        inbounds = config.get("inbounds", [])
        new_inbounds = [i for i in inbounds if i.get("tag") != tag]

        if len(new_inbounds) == len(inbounds):
            return False, f"Inbound '{tag}' not found"

        config["inbounds"] = new_inbounds
        return self.set_config(config, kernel_path, auto_backup=auto_backup)

    def update_inbound(self, tag: str, inbound: dict,
                       kernel_path: Path | None = None,
                       auto_backup: bool = True) -> tuple[bool, str]:
        """Update an existing inbound by tag."""
        config = self.read()
        inbounds = config.get("inbounds", [])

        updated = False
        for i, existing in enumerate(inbounds):
            if existing.get("tag") == tag:
                inbounds[i] = inbound
                updated = True
                break

        if not updated:
            return False, f"Inbound '{tag}' not found"

        config["inbounds"] = inbounds
        return self.set_config(config, kernel_path, auto_backup=auto_backup)
