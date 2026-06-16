"""Attacker profile aggregation."""

from datetime import datetime, timezone

from config import ALERT_THRESHOLD
from database import models


def _ordered_values(serialized, new_value):
    values = [item for item in (serialized or "").split(",") if item]
    if new_value and new_value not in values:
        values.append(new_value)
    return ",".join(values)


def _prefer(new_value, old_value):
    return new_value if new_value not in (None, "") else old_value


def _integer(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def update_attacker_profile(event, increment=True):
    ip_address = event.get("ip_address")
    if not ip_address:
        return False
    timestamp = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    with models.DATABASE_LOCK, models.database_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM attacker_profiles WHERE ip_address = ?", (ip_address,)
        ).fetchone()

        if existing:
            total_attempts = _integer(existing["total_attempts"]) + (
                1 if increment else 0
            )
            last_seen = max(existing["last_seen"] or "", timestamp)
            services = _ordered_values(
                existing["services_targeted"], event.get("service")
            )
            usernames = _ordered_values(
                existing["usernames_tried"], event.get("username_tried")
            )
            passwords = _ordered_values(
                existing["passwords_tried"], event.get("password_tried")
            )
            abuse_score = max(
                _integer(existing["abuse_score"]), _integer(event.get("abuse_score"))
            )
            is_flagged = int(
                abuse_score > 50
                or total_attempts >= ALERT_THRESHOLD
                or bool(existing["is_flagged"])
            )
            location_fields = {
                field: _prefer(event.get(field), existing[field])
                for field in (
                    "country",
                    "country_code",
                    "city",
                    "region",
                    "timezone",
                    "zip_code",
                    "latitude",
                    "longitude",
                    "isp",
                    "org",
                    "country_flag",
                )
            }
            connection.execute(
                """
                UPDATE attacker_profiles SET
                    last_seen = ?,
                    total_attempts = ?,
                    services_targeted = ?,
                    country = ?,
                    country_code = ?,
                    city = ?,
                    region = ?,
                    timezone = ?,
                    zip_code = ?,
                    latitude = ?,
                    longitude = ?,
                    isp = ?,
                    org = ?,
                    country_flag = ?,
                    abuse_score = ?,
                    usernames_tried = ?,
                    passwords_tried = ?,
                    is_flagged = ?
                WHERE ip_address = ?
                """,
                (
                    last_seen,
                    total_attempts,
                    services,
                    location_fields["country"],
                    location_fields["country_code"],
                    location_fields["city"],
                    location_fields["region"],
                    location_fields["timezone"],
                    location_fields["zip_code"],
                    location_fields["latitude"],
                    location_fields["longitude"],
                    location_fields["isp"],
                    location_fields["org"],
                    location_fields["country_flag"],
                    abuse_score,
                    usernames,
                    passwords,
                    is_flagged,
                    ip_address,
                ),
            )
        else:
            total_attempts = 1
            abuse_score = _integer(event.get("abuse_score"))
            is_flagged = int(
                abuse_score > 50 or total_attempts >= ALERT_THRESHOLD
            )
            connection.execute(
                """
                INSERT INTO attacker_profiles (
                    ip_address, first_seen, last_seen, total_attempts,
                    services_targeted, country, country_code, city, region,
                    timezone, zip_code, latitude, longitude, isp, org,
                    country_flag, abuse_score, usernames_tried,
                    passwords_tried, is_flagged
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip_address,
                    timestamp,
                    timestamp,
                    total_attempts,
                    event.get("service") or "",
                    event.get("country") or "",
                    event.get("country_code") or "",
                    event.get("city") or "",
                    event.get("region") or "",
                    event.get("timezone") or "",
                    event.get("zip_code") or "",
                    event.get("latitude"),
                    event.get("longitude"),
                    event.get("isp") or "",
                    event.get("org") or "",
                    event.get("country_flag") or "",
                    abuse_score,
                    event.get("username_tried") or "",
                    event.get("password_tried") or "",
                    is_flagged,
                ),
            )
    return bool(is_flagged)
