"""Application configuration for Honeypot Sentinel."""

import os

from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _get_int_env(name, default, minimum, maximum):
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer between {minimum} and {maximum}"
        ) from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _get_float_env(name, default, minimum, maximum):
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be a number between {minimum} and {maximum}"
        ) from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _get_bool_env(name, default=False):
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _get_csv_env(name):
    raw_value = os.getenv(name, "")
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _get_text_env(name, default=""):
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


SSH_PORT = _get_int_env("SSH_PORT", 2222, 1, 65535)
HTTP_PORT = _get_int_env("HTTP_PORT", 8080, 1, 65535)
FTP_PORT = _get_int_env("FTP_PORT", 2121, 1, 65535)
TELNET_PORT = _get_int_env("TELNET_PORT", 2323, 1, 65535)
FLASK_PORT = _get_int_env("FLASK_PORT", 5000, 1, 65535)
HONEYPOT_HOST = _get_text_env("HONEYPOT_HOST", _get_text_env("HOST", "0.0.0.0"))
FLASK_HOST = _get_text_env("FLASK_HOST", "127.0.0.1")

DB_PATH = os.path.join(BASE_DIR, "database", "events.db")
LOG_PATH = os.path.join(BASE_DIR, "honeypot-sentinel.log")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
MAX_LOG_SIZE = _get_int_env("MAX_LOG_SIZE", 10 * 1024 * 1024, 1024, 1024**3)
LOG_BACKUP_COUNT = _get_int_env("LOG_BACKUP_COUNT", 5, 0, 100)
ALERT_THRESHOLD = _get_int_env("ALERT_THRESHOLD", 5, 1, 100000)

DASHBOARD_USERNAME = _get_text_env("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
API_CORS_ORIGINS = _get_csv_env("API_CORS_ORIGINS")

STORE_SENSITIVE_VALUES = _get_bool_env("STORE_SENSITIVE_VALUES", False)
MAX_EVENT_FIELD_LENGTH = _get_int_env("MAX_EVENT_FIELD_LENGTH", 1024, 64, 65536)
MAX_RAW_DATA_LENGTH = _get_int_env("MAX_RAW_DATA_LENGTH", 16384, 256, 1048576)
MAX_CLIENT_THREADS = _get_int_env("MAX_CLIENT_THREADS", 50, 1, 10000)
ENRICHMENT_QUEUE_SIZE = _get_int_env("ENRICHMENT_QUEUE_SIZE", 1000, 1, 100000)
HTTP_MAX_HEADER_BYTES = _get_int_env("HTTP_MAX_HEADER_BYTES", 65536, 1024, 1048576)
HTTP_MAX_BODY_BYTES = _get_int_env("HTTP_MAX_BODY_BYTES", 262144, 0, 1048576)

GEOIP_LOOKUP_URL = _get_text_env(
    "GEOIP_LOOKUP_URL", "https://ipapi.co/{ip_address}/json/"
)
GEOIP_RATE_INTERVAL = _get_float_env("GEOIP_RATE_INTERVAL", 1.4, 0.0, 60.0)
