import tempfile
import unittest
from pathlib import Path

from database import models


class LoggerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = models.DB_PATH
        models.DB_PATH = str(Path(self.temp_dir.name) / "events.db")

    def tearDown(self):
        models.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def test_log_event_redacts_sensitive_values_by_default(self):
        from honeypot import logger as logger_module

        logger_module.STORE_SENSITIVE_VALUES = False
        event_logger = logger_module.HoneypotLogger(worker_count=0)
        event_id = event_logger.log_event(
            "198.51.100.10",
            "2222",
            "ssh",
            username_tried="admin",
            password_tried="super-secret",
            raw_data="PASS super-secret",
        )

        with models.database_connection() as connection:
            event = connection.execute(
                "SELECT password_tried, raw_data FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()

        self.assertEqual(event["password_tried"], logger_module.REDACTED_VALUE)
        self.assertEqual(event["raw_data"], logger_module.REDACTED_VALUE)


if __name__ == "__main__":
    unittest.main()
