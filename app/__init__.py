import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from app.config import config_by_name

# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """Application factory pattern."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Initialize extensions with app
    db.init_app(app)
    csrf.init_app(app)

    # Read runtime config (env vars that may be set after import time)
    config_class = config_by_name[config_name]
    if hasattr(config_class, 'init_app'):
        config_class.init_app(app)

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.mfa import mfa_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp, url_prefix='/mfa')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    # Register error handlers
    from app.routes.auth import register_error_handlers
    register_error_handlers(app)

    # Create database tables
    with app.app_context():
        from app.models import user, recovery  # noqa: F401
        db.create_all()

    logger.info("Application initialized successfully")
    return app
