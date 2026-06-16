import tempfile
import unittest
from pathlib import Path

from database import models


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = models.DB_PATH
        models.DB_PATH = str(Path(self.temp_dir.name) / "events.db")
        models.init_db()

    def tearDown(self):
        models.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    @staticmethod
    def event(ip_address="198.51.100.10", country="United States", city="Boston"):
        return {
            "timestamp": "2026-06-13T10:00:00+00:00",
            "ip_address": ip_address,
            "port": 2222,
            "service": "SSH",
            "username_tried": "admin",
            "password_tried": "<redacted>",
            "country": country,
            "country_code": "US",
            "city": city,
            "region": "Massachusetts",
            "timezone": "America/New_York",
            "latitude": 42.36,
            "longitude": -71.05,
            "isp": "Example ISP",
            "org": "Example Org",
            "country_flag": "US",
            "abuse_score": 0,
            "is_known_attacker": 0,
        }

    def test_invalid_limits_use_safe_defaults(self):
        models.insert_event(self.event())

        self.assertEqual(len(models.get_all_events(limit="bad")), 1)
        self.assertEqual(len(models.get_events_by_ip("198.51.100.10", limit=None)), 1)
        self.assertEqual(models.get_top_attackers(limit="bad"), [])
        self.assertEqual(len(models.get_alerts(limit="bad")), 0)
        self.assertEqual(len(models.get_top_cities(limit="bad")), 1)

    def test_location_breakdown_includes_top_city_region_and_ip(self):
        models.insert_event(self.event(city="Boston"))
        models.insert_event(self.event(city="Cambridge"))
        models.insert_event(self.event(ip_address="198.51.100.11", city="Boston"))

        breakdown = models.get_location_breakdown(limit="bad")

        self.assertEqual(len(breakdown), 1)
        self.assertEqual(breakdown[0]["country"], "United States")
        self.assertEqual(breakdown[0]["region"], "Massachusetts")
        self.assertEqual(breakdown[0]["top_ip"], "198.51.100.10")
        self.assertEqual(breakdown[0]["cities"][0]["city"], "Boston")


if __name__ == "__main__":
    unittest.main()
