"""Authentication module: password hashing, session management, CSRF protection.

Uses bcrypt for password hashing.
CSRF tokens via session-based double-submit cookie pattern.
"""

import time
import secrets
import hmac
import hashlib
import bcrypt
import logging
from pathlib import Path
from .models import AuthStore

logger = logging.getLogger(__name__)


class AuthManager:
    """Manages admin authentication, sessions, and CSRF tokens."""

    def __init__(self, store: AuthStore, session_duration: int = 60,
                 max_attempts: int = 5, lockout_minutes: int = 15):
        self.store = store
        self.session_duration = session_duration
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes

    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def verify_password(self, password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    def is_initialized(self) -> bool:
        return self.store.has_admin()

    def initialize_admin(self, username: str, password: str):
        if self.is_initialized():
            raise ValueError("Admin already initialized")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        pw_hash = self.hash_password(password)
        self.store.create_admin(username, pw_hash)
        logger.info("Admin account created: %s", username)

    def login(self, username: str, password: str, ip_address: str) -> str | None:
        """Attempt login. Returns session token on success, None on failure."""
        admin = self.store.get_admin()
        if not admin:
            return None

        if admin["username"] != username:
            self.store.record_attempt(ip_address, False)
            return None

        failures = self.store.get_recent_failures(ip_address, self.lockout_minutes)
        if failures >= self.max_attempts:
            logger.warning("Login blocked for IP %s: too many attempts", ip_address)
            raise ValueError("Too many login attempts. Try again later.")

        if not self.verify_password(password, admin["password_hash"]):
            self.store.record_attempt(ip_address, False)
            return None

        self.store.record_attempt(ip_address, True)
        token = self.store.create_session(self.session_duration)
        logger.info("Login successful for %s", username)
        return token

    def logout(self, session_token: str):
        self.store.invalidate_session(session_token)

    def validate_session(self, session_token: str) -> bool:
        if not session_token:
            return False
        self.store.cleanup_expired_sessions()
        return self.store.validate_session(session_token)

    def change_password(self, old_password: str, new_password: str) -> bool:
        admin = self.store.get_admin()
        if not admin:
            return False
        if not self.verify_password(old_password, admin["password_hash"]):
            return False
        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters")
        pw_hash = self.hash_password(new_password)
        self.store.update_password(pw_hash)
        logger.info("Admin password changed")
        return True


class CSRFToken:
    """CSRF protection using HMAC-based tokens.

    Each session gets a CSRF secret. Tokens are derived via HMAC.
    """

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def generate_token(secret: str, salt: str = "") -> str:
        if not salt:
            salt = secrets.token_hex(8)
        h = hmac.new(
            secret.encode("utf-8"),
            salt.encode("utf-8"),
            hashlib.sha256
        )
        return f"{salt}.{h.hexdigest()}"

    @staticmethod
    def validate_token(secret: str, token: str) -> bool:
        if not token or "." not in token:
            return False
        try:
            salt, _ = token.split(".", 1)
            expected = CSRFToken.generate_token(secret, salt)
            return hmac.compare_digest(token, expected)
        except Exception:
            return False
