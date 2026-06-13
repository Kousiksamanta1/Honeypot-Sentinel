"""Flask application factory."""

import os

from flask import Flask
from flask_cors import CORS

from api.routes import api_blueprint
from config import BASE_DIR
from database import models


def create_app():
    models.init_db()
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
        static_folder=os.path.join(BASE_DIR, "dashboard", "static"),
        static_url_path="/static",
    )
    app.config["JSON_SORT_KEYS"] = False
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.register_blueprint(api_blueprint)
    return app
