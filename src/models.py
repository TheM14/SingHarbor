"""Database models and queries for SingHarbor application data."""

import uuid
import logging
from pathlib import Path
from .database import get_db, dict_from_row, dicts_from_rows

logger = logging.getLogger(__name__)


class AuthStore:
    """Admin authentication storage."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def has_admin(self) -> bool:
        conn = get_db(self.db_path)
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM admin").fetchone()
            return row["cnt"] > 0
        finally:
            conn.close()

    def create_admin(self, username: str, password_hash: str):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "INSERT INTO admin (id, username, password_hash) VALUES (1, ?, ?)",
                (username, password_hash)
            )
            conn.commit()
        finally:
            conn.close()

    def get_admin(self) -> dict | None:
        conn = get_db(self.db_path)
        try:
            row = conn.execute("SELECT * FROM admin WHERE id = 1").fetchone()
            return dict_from_row(row)
        finally:
            conn.close()

    def update_password(self, password_hash: str):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "UPDATE admin SET password_hash = ?, updated_at = datetime('now') WHERE id = 1",
                (password_hash,)
            )
            conn.commit()
        finally:
            conn.close()

    def record_attempt(self, ip_address: str, success: bool):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "INSERT INTO login_attempts (ip_address, success) VALUES (?, ?)",
                (ip_address, 1 if success else 0)
            )
            conn.commit()
        finally:
            conn.close()

    def get_recent_failures(self, ip_address: str, since_minutes: int) -> int:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                """SELECT COUNT(*) as cnt FROM login_attempts
                   WHERE ip_address = ? AND success = 0
                   AND attempted_at > datetime('now', ? || ' minutes')""",
                (ip_address, f"-{since_minutes}")
            ).fetchone()
            return row["cnt"]
        finally:
            conn.close()

    def create_session(self, duration_minutes: int) -> str:
        token = uuid.uuid4().hex
        conn = get_db(self.db_path)
        try:
            conn.execute(
                """INSERT INTO sessions (token, expires_at)
                   VALUES (?, datetime('now', ? || ' minutes'))""",
                (token, f"+{duration_minutes}")
            )
            conn.commit()
            return token
        finally:
            conn.close()

    def validate_session(self, token: str) -> bool:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                """SELECT id FROM sessions
                   WHERE token = ? AND active = 1
                   AND expires_at > datetime('now')""",
                (token,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def invalidate_session(self, token: str):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "UPDATE sessions SET active = 0 WHERE token = ?",
                (token,)
            )
            conn.commit()
        finally:
            conn.close()

    def cleanup_expired_sessions(self):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "UPDATE sessions SET active = 0 WHERE expires_at <= datetime('now')"
            )
            conn.commit()
        finally:
            conn.close()


class KernelStore:
    """sing-box kernel version storage."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def add_version(self, version: str, path: str, is_active: bool = False) -> int:
        conn = get_db(self.db_path)
        try:
            if is_active:
                conn.execute("UPDATE kernel_versions SET is_active = 0")
            cur = conn.execute(
                """INSERT INTO kernel_versions (version, path, is_active)
                   VALUES (?, ?, ?)
                   ON CONFLICT(version) DO UPDATE SET path = excluded.path""",
                (version, path, 1 if is_active else 0)
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_active(self) -> dict | None:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM kernel_versions WHERE is_active = 1"
            ).fetchone()
            return dict_from_row(row)
        finally:
            conn.close()

    def set_active(self, version: str):
        conn = get_db(self.db_path)
        try:
            conn.execute("UPDATE kernel_versions SET is_active = 0")
            conn.execute(
                "UPDATE kernel_versions SET is_active = 1 WHERE version = ?",
                (version,)
            )
            conn.commit()
        finally:
            conn.close()

    def set_pinned(self, version: str, pinned: bool):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "UPDATE kernel_versions SET is_pinned = ? WHERE version = ?",
                (1 if pinned else 0, version)
            )
            conn.commit()
        finally:
            conn.close()

    def get_all(self) -> list[dict]:
        conn = get_db(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM kernel_versions ORDER BY installed_at DESC"
            ).fetchall()
            return dicts_from_rows(rows)
        finally:
            conn.close()

    def get_by_version(self, version: str) -> dict | None:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM kernel_versions WHERE version = ?", (version,)
            ).fetchone()
            return dict_from_row(row)
        finally:
            conn.close()

    def has_version(self, version: str) -> bool:
        return self.get_by_version(version) is not None

    def remove_version(self, version: str):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "DELETE FROM kernel_versions WHERE version = ?", (version,)
            )
            conn.commit()
        finally:
            conn.close()


class ConfigHistoryStore:
    """Configuration backup and history tracking."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def add_entry(self, config_hash: str, backup_path: str,
                  operation: str, description: str = "") -> int:
        conn = get_db(self.db_path)
        try:
            cur = conn.execute(
                """INSERT INTO config_history (config_hash, backup_path, operation, description)
                   VALUES (?, ?, ?, ?)""",
                (config_hash, backup_path, operation, description)
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_history(self, limit: int = 50) -> list[dict]:
        conn = get_db(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM config_history ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return dicts_from_rows(rows)
        finally:
            conn.close()

    def get_by_id(self, entry_id: int) -> dict | None:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM config_history WHERE id = ?", (entry_id,)
            ).fetchone()
            return dict_from_row(row)
        finally:
            conn.close()


class OperationLogStore:
    """Operation audit log."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def log(self, action: str, result: str, details: str = ""):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "INSERT INTO operation_log (action, details, result) VALUES (?, ?, ?)",
                (action, details, result)
            )
            conn.commit()
        finally:
            conn.close()

    def get_recent(self, limit: int = 100) -> list[dict]:
        conn = get_db(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM operation_log ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return dicts_from_rows(rows)
        finally:
            conn.close()


class ProtocolStore:
    """Protocol instance metadata storage."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def add_instance(self, tag: str, protocol: str, listen_address: str,
                     listen_port: int, config_snippet: str = "{}",
                     managed: bool = True) -> int:
        conn = get_db(self.db_path)
        try:
            cur = conn.execute(
                """INSERT INTO protocol_instances
                   (tag, protocol, listen_address, listen_port, config_snippet, managed)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (tag, protocol, listen_address, listen_port, config_snippet,
                 1 if managed else 0)
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_all(self) -> list[dict]:
        conn = get_db(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM protocol_instances ORDER BY created_at DESC"
            ).fetchall()
            return dicts_from_rows(rows)
        finally:
            conn.close()

    def get_by_tag(self, tag: str) -> dict | None:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM protocol_instances WHERE tag = ?", (tag,)
            ).fetchone()
            return dict_from_row(row)
        finally:
            conn.close()

    def get_by_port(self, port: int) -> dict | None:
        conn = get_db(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM protocol_instances WHERE listen_port = ?", (port,)
            ).fetchone()
            return dict_from_row(row)
        finally:
            conn.close()

    def update_instance(self, tag: str, **kwargs):
        conn = get_db(self.db_path)
        try:
            fields = ", ".join(f"{k} = ?" for k in kwargs)
            values = list(kwargs.values()) + [tag]
            conn.execute(
                f"UPDATE protocol_instances SET {fields}, updated_at = datetime('now') WHERE tag = ?",
                values
            )
            conn.commit()
        finally:
            conn.close()

    def remove_instance(self, tag: str):
        conn = get_db(self.db_path)
        try:
            conn.execute(
                "DELETE FROM protocol_instances WHERE tag = ?", (tag,)
            )
            conn.commit()
        finally:
            conn.close()
