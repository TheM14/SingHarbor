"""Flask application factory for SingHarbor.

Creates and configures the Flask app with all components.
"""

import os
import sys
import logging
from pathlib import Path

from flask import Flask, request, g
from .config import AppConfig
from .database import init_db
from .models import AuthStore, KernelStore, ConfigHistoryStore, OperationLogStore, ProtocolStore
from .auth import AuthManager
from .platform import detect_platform_info
from .sandbox import set_allowed_dirs


def create_app(config_path: Path | None = None,
               instance_path: Path | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_path: Path to SingHarbor config JSON.
        instance_path: Path for Flask instance folder.
    """
    project_root = (
        Path(instance_path).resolve()
        if instance_path is not None
        else Path(__file__).parent.parent
    )
    app_cfg = AppConfig(config_path, project_root=project_root)
    app_cfg.ensure_dirs()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(app_cfg.log_dir / "singharbor.log", encoding="utf-8"),
        ],
    )
    logger = logging.getLogger(__name__)

    init_db(app_cfg.db_path)

    set_allowed_dirs(
        app_cfg.data_dir,
        app_cfg.kernels_dir,
        app_cfg.backup_dir,
        app_cfg.downloads_dir,
    )

    auth_store = AuthStore(app_cfg.db_path)
    kernel_store = KernelStore(app_cfg.db_path)
    config_history_store = ConfigHistoryStore(app_cfg.db_path)
    operation_log_store = OperationLogStore(app_cfg.db_path)
    protocol_store = ProtocolStore(app_cfg.db_path)

    auth_mgr = AuthManager(
        auth_store,
        session_duration=app_cfg.session_duration_minutes,
        max_attempts=app_cfg.login_max_attempts,
        lockout_minutes=app_cfg.login_lockout_minutes,
    )

    from .kernel import KernelManager
    kernel_mgr = KernelManager(app_cfg.kernels_dir)

    from .process import ProcessManager
    process_mgr = ProcessManager(app_cfg.data_dir / "runtime")

    from .config_mgr import ConfigManager
    config_mgr = ConfigManager(
        app_cfg.data_dir / "sing-box-config.json",
        app_cfg.backup_dir,
        kernel_mgr,
    )

    from .wizard import DeploymentWizard
    wizard = DeploymentWizard(config_mgr, kernel_mgr, process_mgr, app_cfg)

    from .certificates import LetsEncryptIssuer
    from .quick_deploy import QuickDeploymentService
    certificate_issuer = LetsEncryptIssuer(app_cfg.data_dir)
    quick_deployment = QuickDeploymentService(
        config_mgr, process_mgr, app_cfg, certificate_issuer
    )

    flask_options = {
        "template_folder": Path(__file__).parent.parent / "web" / "templates",
        "static_folder": Path(__file__).parent.parent / "web" / "static",
    }
    if instance_path is not None:
        flask_options["instance_path"] = str(Path(instance_path).resolve())
    app = Flask(__name__, **flask_options)
    app.secret_key = app_cfg.secret_key
    app.config["app_config"] = app_cfg
    app.config["auth_manager"] = auth_mgr
    app.config["auth_store"] = auth_store
    app.config["kernel_manager"] = kernel_mgr
    app.config["kernel_store"] = kernel_store
    app.config["process_manager"] = process_mgr
    app.config["config_manager"] = config_mgr
    app.config["config_history_store"] = config_history_store
    app.config["operation_log_store"] = operation_log_store
    app.config["protocol_store"] = protocol_store
    app.config["deployment_wizard"] = wizard
    app.config["certificate_issuer"] = certificate_issuer
    app.config["quick_deployment"] = quick_deployment

    from .views import auth_bp, setup_bp, api_bp, ui_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(setup_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(ui_bp)

    from .i18n import get_text

    @app.before_request
    def detect_language():
        g.lang = request.cookies.get("sh_lang", "en")
        if g.lang not in ("en", "zh"):
            g.lang = "en"

    @app.context_processor
    def inject_globals():
        platform_info = detect_platform_info()
        from . import __version__, __sing_box_target__
        return {
            "app_version": __version__,
            "singbox_target": __sing_box_target__,
            "platform_os": platform_info["python_os"],
            "platform_arch": platform_info["arch"],
            "t": lambda k: get_text(g.lang, k),
            "lang": g.lang,
        }

    logger.info("SingHarbor application initialized")
    logger.info("Data directory: %s", app_cfg.data_dir)
    logger.info("Configuration file: %s", app_cfg.config_file_path)
    logger.info("Database: %s", app_cfg.db_path)

    return app
