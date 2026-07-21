"""View package - imports all view blueprints."""

from .auth_views import auth_bp
from .setup_views import setup_bp
from .api_views import api_bp
from .ui_views import ui_bp

__all__ = ["auth_bp", "setup_bp", "api_bp", "ui_bp"]
