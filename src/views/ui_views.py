"""UI views: serves the HTML pages of the WebUI."""

import logging
from flask import Blueprint, render_template, redirect, url_for, current_app
from .auth_views import login_required

logger = logging.getLogger(__name__)

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def index():
    auth_mgr = current_app.config["auth_manager"]
    if not auth_mgr.is_initialized():
        return redirect(url_for("ui.setup_page"))
    return redirect(url_for("ui.dashboard"))


@ui_bp.route("/setup")
def setup_page():
    auth_mgr = current_app.config["auth_manager"]
    if auth_mgr.is_initialized():
        return redirect(url_for("ui.login_page"))
    return render_template("setup.html")


@ui_bp.route("/login")
def login_page():
    auth_mgr = current_app.config["auth_manager"]
    if not auth_mgr.is_initialized():
        return redirect(url_for("ui.setup_page"))
    return render_template("login.html")


@ui_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@ui_bp.route("/dashboard/kernel")
@login_required
def kernel_page():
    return render_template("kernel.html")


@ui_bp.route("/dashboard/config")
@login_required
def config_page():
    return render_template("config.html")


@ui_bp.route("/dashboard/protocols")
@login_required
def protocols_page():
    return render_template("protocols.html")


@ui_bp.route("/dashboard/wizard")
@login_required
def wizard_page():
    return render_template("wizard.html")


@ui_bp.route("/dashboard/quick-deploy")
@login_required
def quick_deploy_page():
    return render_template("quick_deploy.html")


@ui_bp.route("/dashboard/inbounds")
@login_required
def inbounds_page():
    return render_template("inbounds.html")


@ui_bp.route("/dashboard/settings")
@login_required
def settings_page():
    return render_template("settings.html")
