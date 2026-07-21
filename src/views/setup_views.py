"""Setup views: admin initialization wizard."""

import logging
from flask import Blueprint, request, jsonify, current_app

logger = logging.getLogger(__name__)

setup_bp = Blueprint("setup", __name__, url_prefix="/setup")


@setup_bp.route("/initialize", methods=["POST"])
def initialize():
    """Initialize the admin account. Only works when no admin exists."""
    auth_mgr = current_app.config["auth_manager"]

    if auth_mgr.is_initialized():
        return jsonify({"error": "Admin already initialized"}), 400

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Username required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    try:
        auth_mgr.initialize_admin(username, password)
        return jsonify({"success": True, "message": "Admin account created"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Setup failed: %s", e)
        return jsonify({"error": "Setup failed"}), 500


@setup_bp.route("/status", methods=["GET"])
def status():
    """Check setup status."""
    auth_mgr = current_app.config["auth_manager"]
    return jsonify({"initialized": auth_mgr.is_initialized()})
