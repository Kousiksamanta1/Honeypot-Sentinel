import unittest

from enrichment import geoip


class GeoIpTests(unittest.TestCase):
    def test_normalizes_ipapi_payload(self):
        result = geoip._normalize_payload(
            {
                "ip": "8.8.8.8",
                "city": "Mountain View",
                "region": "California",
                "country_code": "US",
                "country_name": "United States",
                "postal": "94035",
                "latitude": 37.386,
                "longitude": -122.0838,
                "timezone": "America/Los_Angeles",
                "org": "Google LLC",
            }
        )

        self.assertEqual(result["country"], "United States")
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["zip_code"], "94035")
        self.assertEqual(result["latitude"], 37.386)
        self.assertEqual(result["org"], "Google LLC")

    def test_normalizes_legacy_ip_api_payload(self):
        result = geoip._normalize_payload(
            {
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "regionName": "California",
                "city": "Mountain View",
                "zip": "94035",
                "lat": 37.386,
                "lon": -122.0838,
                "timezone": "America/Los_Angeles",
                "isp": "Google",
                "org": "Google LLC",
                "as": "AS15169 Google LLC",
            }
        )

        self.assertEqual(result["country"], "United States")
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["region"], "California")
        self.assertEqual(result["longitude"], -122.0838)
        self.assertEqual(result["as"], "AS15169 Google LLC")

    def test_error_payload_returns_empty_result(self):
        self.assertEqual(geoip._normalize_payload({"error": True}), {})


if __name__ == "__main__":
    unittest.main()
