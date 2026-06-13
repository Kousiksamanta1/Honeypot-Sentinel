import tempfile
import unittest
from pathlib import Path

from database import models
from enrichment import profiler


class ProfilerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = models.DB_PATH
        self.original_threshold = profiler.ALERT_THRESHOLD
        models.DB_PATH = str(Path(self.temp_dir.name) / "events.db")
        profiler.ALERT_THRESHOLD = 3
        models.init_db()

    def tearDown(self):
        models.DB_PATH = self.original_db_path
        profiler.ALERT_THRESHOLD = self.original_threshold
        self.temp_dir.cleanup()

    @staticmethod
    def event(timestamp, service="SSH", abuse_score=0):
        return {
            "timestamp": timestamp,
            "ip_address": "192.0.2.10",
            "service": service,
            "username_tried": "admin",
            "password_tried": "password",
            "abuse_score": abuse_score,
        }

    def test_profile_is_flagged_when_attempt_threshold_is_reached(self):
        self.assertFalse(
            profiler.update_attacker_profile(
                self.event("2026-06-13T10:00:00+00:00")
            )
        )
        self.assertFalse(
            profiler.update_attacker_profile(
                self.event("2026-06-13T10:01:00+00:00", service="HTTP")
            )
        )
        self.assertTrue(
            profiler.update_attacker_profile(
                self.event("2026-06-13T10:02:00+00:00", service="FTP")
            )
        )

        with models.database_connection() as connection:
            profile = connection.execute(
                "SELECT * FROM attacker_profiles WHERE ip_address = ?",
                ("192.0.2.10",),
            ).fetchone()

        self.assertEqual(profile["total_attempts"], 3)
        self.assertEqual(profile["is_flagged"], 1)
        self.assertEqual(profile["services_targeted"], "SSH,HTTP,FTP")

    def test_high_abuse_score_flags_first_attempt(self):
        self.assertTrue(
            profiler.update_attacker_profile(
                self.event("2026-06-13T11:00:00+00:00", abuse_score=80)
            )
        )

    def test_ordered_values_ignores_duplicates_and_empty_values(self):
        self.assertEqual(profiler._ordered_values("SSH,HTTP", "SSH"), "SSH,HTTP")
        self.assertEqual(profiler._ordered_values("SSH", "FTP"), "SSH,FTP")
        self.assertEqual(profiler._ordered_values("SSH", ""), "SSH")


if __name__ == "__main__":
    unittest.main()

