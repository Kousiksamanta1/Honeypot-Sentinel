import base64
import tempfile
import unittest
from pathlib import Path

import api as api_module
from database import models


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = models.DB_PATH
        self.original_flask_host = api_module.FLASK_HOST
        self.original_dashboard_password = api_module.DASHBOARD_PASSWORD
        self.original_dashboard_username = api_module.DASHBOARD_USERNAME
        self.original_cors_origins = list(api_module.API_CORS_ORIGINS)
        models.DB_PATH = str(Path(self.temp_dir.name) / "events.db")
        api_module.FLASK_HOST = "127.0.0.1"
        api_module.DASHBOARD_USERNAME = "admin"
        api_module.DASHBOARD_PASSWORD = ""
        api_module.API_CORS_ORIGINS = []

    def tearDown(self):
        models.DB_PATH = self.original_db_path
        api_module.FLASK_HOST = self.original_flask_host
        api_module.DASHBOARD_PASSWORD = self.original_dashboard_password
        api_module.DASHBOARD_USERNAME = self.original_dashboard_username
        api_module.API_CORS_ORIGINS = self.original_cors_origins
        self.temp_dir.cleanup()

    @staticmethod
    def auth_header(username, password):
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
            "ascii"
        )
        return {"Authorization": f"Basic {token}"}

    def test_invalid_service_filter_returns_400(self):
        app = api_module.create_app()
        response = app.test_client().get("/api/events?service=smtp")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Unsupported service filter")

    def test_default_api_response_does_not_allow_cross_origin(self):
        app = api_module.create_app()
        response = app.test_client().get(
            "/api/stats", headers={"Origin": "https://example.invalid"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_basic_auth_protects_dashboard_when_password_is_set(self):
        api_module.DASHBOARD_PASSWORD = "secret"
        app = api_module.create_app()
        client = app.test_client()

        self.assertEqual(client.get("/").status_code, 401)
        self.assertEqual(
            client.get("/", headers=self.auth_header("admin", "secret")).status_code,
            200,
        )
        self.assertEqual(client.get("/healthz").status_code, 200)

    def test_external_bind_requires_dashboard_password(self):
        api_module.FLASK_HOST = "0.0.0.0"
        api_module.DASHBOARD_PASSWORD = ""

        with self.assertRaises(RuntimeError):
            api_module.create_app()


if __name__ == "__main__":
    unittest.main()
