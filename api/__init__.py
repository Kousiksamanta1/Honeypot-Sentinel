"""Flask application factory."""

import hmac
import os

from flask import Flask, Response, request
from flask_cors import CORS

from api.routes import api_blueprint
from config import (
    API_CORS_ORIGINS,
    BASE_DIR,
    DASHBOARD_PASSWORD,
    DASHBOARD_USERNAME,
    FLASK_HOST,
)
from database import models


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _dashboard_is_externally_bound():
    return FLASK_HOST not in _LOOPBACK_HOSTS


def _unauthorized_response():
    return Response(
        "Authentication required\n",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="Honeypot Sentinel"'},
    )


def _install_basic_auth(app):
    if not DASHBOARD_PASSWORD:
        if _dashboard_is_externally_bound():
            raise RuntimeError(
                "DASHBOARD_PASSWORD is required when FLASK_HOST is not loopback"
            )
        return

    @app.before_request
    def require_basic_auth():
        if request.path == "/healthz":
            return None
        auth = request.authorization
        if auth is None:
            return _unauthorized_response()
        username_ok = hmac.compare_digest(auth.username or "", DASHBOARD_USERNAME)
        password_ok = hmac.compare_digest(auth.password or "", DASHBOARD_PASSWORD)
        if not username_ok or not password_ok:
            return _unauthorized_response()
        return None


def create_app():
    models.init_db()
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
        static_folder=os.path.join(BASE_DIR, "dashboard", "static"),
        static_url_path="/static",
    )
    app.config["JSON_SORT_KEYS"] = False
    if API_CORS_ORIGINS:
        CORS(app, resources={r"/api/*": {"origins": API_CORS_ORIGINS}})
    _install_basic_auth(app)
    app.register_blueprint(api_blueprint)
    return app
