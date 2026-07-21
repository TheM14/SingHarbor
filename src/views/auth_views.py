"""Authentication views: login, logout, password change."""

import functools
import logging
from flask import (
    Blueprint, request, jsonify, session, g, current_app, redirect, url_for
)
from ..auth import AuthManager, CSRFToken

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def get_auth_manager() -> AuthManager:
    return current_app.config["auth_manager"]


def login_required(view_func):
    """Decorator to require authenticated session."""
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("sh_session")
        auth_mgr = get_auth_manager()
        if not token or not auth_mgr.validate_session(token):
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("ui.login_page"))
        g.session_token = token
        return view_func(*args, **kwargs)
    return wrapper


def csrf_protected(view_func):
    """Decorator to require CSRF token for mutation operations."""
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return view_func(*args, **kwargs)

        csrf_secret = session.get("csrf_secret", "")
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")

        if not CSRFToken.validate_token(csrf_secret, token):
            return jsonify({"error": "CSRF validation failed"}), 403

        return view_func(*args, **kwargs)
    return wrapper


def get_csrf_token():
    """Generate a CSRF token for the current session."""
    if "csrf_secret" not in session:
        session["csrf_secret"] = CSRFToken.generate_secret()
    return CSRFToken.generate_token(session["csrf_secret"])


@auth_bp.route("/login", methods=["POST"])
def login():
    """Handle login."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    auth_mgr = get_auth_manager()
    ip = request.remote_addr or "unknown"

    try:
        token = auth_mgr.login(username, password, ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 429

    if token is None:
        return jsonify({"error": "Invalid credentials"}), 401

    session["csrf_secret"] = CSRFToken.generate_secret()

    resp = jsonify({"success": True, "csrf_token": get_csrf_token()})
    resp.set_cookie(
        "sh_session", token,
        httponly=True,
        samesite="Lax",
        max_age=auth_mgr.session_duration * 60,
    )
    return resp


@auth_bp.route("/logout", methods=["POST"])
@login_required
@csrf_protected
def logout():
    """Handle logout."""
    auth_mgr = get_auth_manager()
    token = request.cookies.get("sh_session", "")
    auth_mgr.logout(token)

    resp = jsonify({"success": True})
    resp.delete_cookie("sh_session")
    session.clear()
    return resp


@auth_bp.route("/change-password", methods=["POST"])
@login_required
@csrf_protected
def change_password():
    """Change admin password."""
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    if not old_password or not new_password:
        return jsonify({"error": "Both passwords required"}), 400

    auth_mgr = get_auth_manager()
    try:
        ok = auth_mgr.change_password(old_password, new_password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not ok:
        return jsonify({"error": "Current password is incorrect"}), 400

    return jsonify({"success": True})


@auth_bp.route("/status", methods=["GET"])
def check_auth():
    """Check if the current session is authenticated."""
    token = request.cookies.get("sh_session")
    auth_mgr = get_auth_manager()
    initialized = auth_mgr.is_initialized()
    lang = request.cookies.get("sh_lang", "en")

    if not initialized:
        return jsonify({"authenticated": False, "initialized": False, "lang": lang})

    if token and auth_mgr.validate_session(token):
        return jsonify({"authenticated": True, "initialized": True,
                        "csrf_token": get_csrf_token(), "lang": lang})

    return jsonify({"authenticated": False, "initialized": True, "lang": lang})
