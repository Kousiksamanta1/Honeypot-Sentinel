"""Thread-safe SQLite persistence and reporting helpers."""

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from config import DB_PATH


DATABASE_LOCK = threading.RLock()

EVENT_COLUMNS = (
    "timestamp",
    "ip_address",
    "port",
    "service",
    "username_tried",
    "password_tried",
    "command_tried",
    "raw_data",
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
    "abuse_score",
    "is_known_attacker",
)


def _bounded_int(value, default, minimum, maximum):
    try:
        integer = int(value)
    except (TypeError, ValueError):
        integer = default
    return max(minimum, min(integer, maximum))


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database_connection():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with DATABASE_LOCK, database_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip_address TEXT,
                port INTEGER,
                service TEXT,
                username_tried TEXT,
                password_tried TEXT,
                command_tried TEXT,
                raw_data TEXT,
                country TEXT,
                country_code TEXT,
                city TEXT,
                region TEXT,
                timezone TEXT,
                zip_code TEXT,
                latitude REAL,
                longitude REAL,
                isp TEXT,
                org TEXT,
                country_flag TEXT,
                abuse_score INTEGER DEFAULT 0,
                is_known_attacker INTEGER DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                ip_address TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                total_attempts INTEGER,
                services_targeted TEXT,
                country TEXT,
                country_code TEXT,
                city TEXT,
                region TEXT,
                timezone TEXT,
                zip_code TEXT,
                latitude REAL,
                longitude REAL,
                isp TEXT,
                org TEXT,
                country_flag TEXT,
                abuse_score INTEGER DEFAULT 0,
                usernames_tried TEXT,
                passwords_tried TEXT,
                is_flagged INTEGER DEFAULT 0
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_service ON events(service)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_country ON events(country)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_country_city ON events(country, city)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_country_region ON events(country, region)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_country_ip ON events(country, ip_address)"
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_profiles_attempts
            ON attacker_profiles(total_attempts DESC, abuse_score DESC, last_seen DESC)
            """
        )


def insert_event(event):
    values = [event.get(column) for column in EVENT_COLUMNS]
    placeholders = ", ".join("?" for _ in EVENT_COLUMNS)
    columns = ", ".join(EVENT_COLUMNS)
    with DATABASE_LOCK, database_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO events ({columns}) VALUES ({placeholders})", values
        )
        return cursor.lastrowid


def update_event_enrichment(event_id, enrichment, is_known_attacker=0):
    fields = (
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
        "abuse_score",
    )
    assignments = ", ".join(f"{field} = ?" for field in fields)
    values = [enrichment.get(field) for field in fields]
    values.extend((int(bool(is_known_attacker)), event_id))
    with DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            f"""
            UPDATE events
            SET {assignments}, is_known_attacker = ?
            WHERE id = ?
            """,
            values,
        )


def mark_event_known(event_id, is_known_attacker):
    with DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            "UPDATE events SET is_known_attacker = ? WHERE id = ?",
            (int(bool(is_known_attacker)), event_id),
        )


def get_all_events(limit=50, service=None, country=None):
    limit = _bounded_int(limit, 50, 1, 1000)
    conditions = []
    parameters = []
    if service:
        conditions.append("service = ?")
        parameters.append(service.upper())
    if country:
        conditions.append("country = ?")
        parameters.append(country)
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    parameters.append(limit)
    with DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT * FROM events
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
            """,
            parameters,
        ).fetchall()
    return [dict(row) for row in rows]


def get_recent_events(limit=50):
    return get_all_events(limit=limit)


def get_events_by_ip(ip_address, limit=100):
    limit = _bounded_int(limit, 100, 1, 1000)
    with DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            WHERE ip_address = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (ip_address, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def _query_counts(connection, expression, alias, limit=None, where=None):
    where_clause = f"WHERE {where}" if where else ""
    limit_clause = "LIMIT ?" if limit else ""
    parameters = (limit,) if limit else ()
    rows = connection.execute(
        f"""
        SELECT {expression} AS {alias}, COUNT(*) AS count
        FROM events
        {where_clause}
        GROUP BY {expression}
        ORDER BY count DESC, {alias} ASC
        {limit_clause}
        """,
        parameters,
    ).fetchall()
    return [dict(row) for row in rows]


def _events_per_hour(connection):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=23)
    rows = connection.execute(
        """
        SELECT timestamp FROM events
        WHERE timestamp >= ?
        ORDER BY timestamp ASC
        """,
        (start.isoformat(),),
    ).fetchall()
    buckets = {
        (start + timedelta(hours=index)).strftime("%Y-%m-%dT%H:00:00Z"): 0
        for index in range(24)
    }
    for row in rows:
        try:
            parsed = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            parsed = parsed.astimezone(timezone.utc).replace(
                minute=0, second=0, microsecond=0
            )
            key = parsed.strftime("%Y-%m-%dT%H:00:00Z")
            if key in buckets:
                buckets[key] += 1
        except (AttributeError, TypeError, ValueError):
            continue
    return [{"hour": hour, "count": count} for hour, count in buckets.items()]


def get_stats():
    with DATABASE_LOCK, database_connection() as connection:
        total_events = connection.execute(
            "SELECT COUNT(*) AS count FROM events"
        ).fetchone()["count"]
        unique_attackers = connection.execute(
            "SELECT COUNT(DISTINCT ip_address) AS count FROM events"
        ).fetchone()["count"]
        known_attackers = connection.execute(
            "SELECT COUNT(*) AS count FROM attacker_profiles WHERE is_flagged = 1"
        ).fetchone()["count"]
        total_countries = connection.execute(
            """
            SELECT COUNT(DISTINCT country) AS count
            FROM events
            WHERE country IS NOT NULL AND country != ''
            """
        ).fetchone()["count"]
        country_rows = connection.execute(
            """
            SELECT country, country_code, country_flag AS flag, COUNT(*) AS count
            FROM events
            WHERE country IS NOT NULL AND country != ''
            GROUP BY country, country_code, country_flag
            ORDER BY count DESC, country ASC
            LIMIT 10
            """
        ).fetchall()
        top_services = _query_counts(
            connection, "service", "service", where="service IS NOT NULL"
        )
        top_usernames = _query_counts(
            connection,
            "username_tried",
            "username",
            limit=10,
            where="username_tried IS NOT NULL AND username_tried != ''",
        )
        top_passwords = _query_counts(
            connection,
            "password_tried",
            "password",
            limit=10,
            where="password_tried IS NOT NULL AND password_tried != ''",
        )
        regions = _query_counts(
            connection,
            "region",
            "region",
            limit=20,
            where="region IS NOT NULL AND region != ''",
        )
        timezones = _query_counts(
            connection,
            "timezone",
            "timezone",
            limit=20,
            where="timezone IS NOT NULL AND timezone != ''",
        )
        hourly = _events_per_hour(connection)
    top_countries = [dict(row) for row in country_rows]
    return {
        "total_events": total_events,
        "unique_attackers": unique_attackers,
        "known_attackers": known_attackers,
        "total_countries": total_countries,
        "top_countries": top_countries,
        "top_services": top_services,
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
        "events_per_hour": hourly,
        "attacks_by_region": regions,
        "attacks_by_timezone": timezones,
        "most_attacked_from": top_countries[0]["country"] if top_countries else "N/A",
    }


def _profile_to_dict(row):
    if row is None:
        return None
    profile = dict(row)
    for field in ("services_targeted", "usernames_tried", "passwords_tried"):
        profile[field] = [
            value for value in (profile.get(field) or "").split(",") if value
        ]
    return profile


def get_attacker_profile(ip_address):
    with DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM attacker_profiles WHERE ip_address = ?", (ip_address,)
        ).fetchone()
    return _profile_to_dict(row)


def get_top_attackers(limit=20):
    limit = _bounded_int(limit, 20, 1, 100)
    with DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM attacker_profiles
            ORDER BY total_attempts DESC, abuse_score DESC, last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_profile_to_dict(row) for row in rows]


def get_map_data():
    with DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                ip_address AS ip,
                MAX(latitude) AS lat,
                MAX(longitude) AS lon,
                MAX(country) AS country,
                MAX(country_code) AS country_code,
                MAX(country_flag) AS flag,
                MAX(city) AS city,
                MAX(region) AS region,
                MAX(timezone) AS timezone,
                MAX(isp) AS isp,
                MAX(org) AS org,
                COUNT(*) AS count,
                MAX(abuse_score) AS abuse_score,
                MAX(is_known_attacker) AS is_known_attacker
            FROM events
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            GROUP BY ip_address
            ORDER BY count DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_alerts(limit=20):
    limit = _bounded_int(limit, 20, 1, 100)
    with DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM events
            WHERE is_known_attacker = 1 OR abuse_score > 50
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_location_breakdown(limit=100):
    limit = _bounded_int(limit, 100, 1, 500)
    with DATABASE_LOCK, database_connection() as connection:
        country_rows = connection.execute(
            """
            SELECT country, country_code, country_flag AS flag, COUNT(*) AS count
            FROM events
            WHERE country IS NOT NULL AND country != ''
            GROUP BY country, country_code, country_flag
            ORDER BY count DESC, country ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        countries = [dict(row) for row in country_rows]
        country_names = [country["country"] for country in countries]
        if not country_names:
            return []

        placeholders = ", ".join("?" for _ in country_names)
        city_rows = connection.execute(
            f"""
            SELECT country, city, COUNT(*) AS count
            FROM events
            WHERE country IN ({placeholders}) AND city IS NOT NULL AND city != ''
            GROUP BY country, city
            ORDER BY country ASC, count DESC, city ASC
            """,
            country_names,
        ).fetchall()
        region_rows = connection.execute(
            f"""
            SELECT country, region, COUNT(*) AS count
            FROM events
            WHERE country IN ({placeholders}) AND region IS NOT NULL AND region != ''
            GROUP BY country, region
            ORDER BY country ASC, count DESC, region ASC
            """,
            country_names,
        ).fetchall()
        top_ip_rows = connection.execute(
            f"""
            SELECT country, ip_address, COUNT(*) AS count
            FROM events
            WHERE country IN ({placeholders}) AND ip_address IS NOT NULL
            GROUP BY country, ip_address
            ORDER BY country ASC, count DESC, ip_address ASC
            """,
            country_names,
        ).fetchall()

    cities_by_country = {country: [] for country in country_names}
    for city_row in city_rows:
        country = city_row["country"]
        if len(cities_by_country[country]) < 5:
            cities_by_country[country].append(dict(city_row))

    region_by_country = {}
    for region_row in region_rows:
        region_by_country.setdefault(region_row["country"], region_row["region"])

    top_ip_by_country = {}
    for ip_row in top_ip_rows:
        top_ip_by_country.setdefault(ip_row["country"], ip_row["ip_address"])

    for item in countries:
        country = item["country"]
        item["cities"] = cities_by_country.get(country, [])
        item["region"] = region_by_country.get(country, "")
        item["top_ip"] = top_ip_by_country.get(country, "")
    return countries


def get_top_cities(limit=20):
    limit = _bounded_int(limit, 20, 1, 100)
    with DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                city,
                MAX(country) AS country,
                MAX(country_flag) AS flag,
                COUNT(*) AS count,
                MAX(isp) AS isp
            FROM events
            WHERE city IS NOT NULL AND city != ''
            GROUP BY city, country
            ORDER BY count DESC, city ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
