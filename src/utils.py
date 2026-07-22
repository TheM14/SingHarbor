"""Utility functions for SingHarbor."""

import re
import uuid
import hashlib
import secrets
import base64
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)

SENSITIVE_KEYS = {
    "password", "uuid", "private_key", "secret", "token",
    "psk", "auth", "key", "credentials", "api_token",
    "cloudflare_api_token",
}

LOG_MASK = "***"


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_password(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generate_ss_password(length: int = 16) -> str:
    raw = secrets.token_bytes(length)
    return base64.b64encode(raw).decode("ascii")


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def mask_sensitive(text: str) -> str:
    """Mask sensitive information in log/text output."""
    for key in SENSITIVE_KEYS:
        text = re.sub(
            rf'("{key}"\s*:\s*)"[^"]*"',
            rf'\1"{LOG_MASK}"',
            text,
            flags=re.IGNORECASE
        )
        text = re.sub(
            rf'("{key}"\s*:\s*)(?!")([^,\s}}\]]+)',
            rf'\1"{LOG_MASK}"',
            text,
            flags=re.IGNORECASE
        )
    return text


def mask_dict_sensitive(data: dict) -> dict:
    """Return a copy of dict with sensitive values masked."""
    if not isinstance(data, dict):
        return data
    result = {}
    for k, v in data.items():
        if k.lower() in SENSITIVE_KEYS:
            result[k] = LOG_MASK
        elif isinstance(v, dict):
            result[k] = mask_dict_sensitive(v)
        elif isinstance(v, list):
            result[k] = [
                mask_dict_sensitive(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            result[k] = v
    return result


def json_load_keep_unknown(path: Path) -> dict:
    """Load JSON while preserving all fields including unknown ones."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def json_save_atomic(data: dict, path: Path):
    """Atomically write JSON data to a file.

    Writes to a temp file first, then renames.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp_path = parent / f".{path.name}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        tmp_path.replace(path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def deep_merge(base: dict, overlay: dict) -> dict:
    """Deep merge two dicts. overlay values override base values."""
    result = dict(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def generate_diff_dict(old: dict, new: dict) -> dict:
    """Generate a simplified diff between two dicts."""
    diff = {}
    all_keys = set(old.keys()) | set(new.keys())
    for key in sorted(all_keys):
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            if old_val is None:
                diff[key] = {"action": "added", "value": new_val}
            elif new_val is None:
                diff[key] = {"action": "removed", "value": old_val}
            else:
                diff[key] = {"action": "changed", "old": old_val, "new": new_val}
    return diff
