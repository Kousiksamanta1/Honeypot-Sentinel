"""Application configuration for Honeypot Sentinel."""

import os

from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))
FTP_PORT = int(os.getenv("FTP_PORT", "2121"))
TELNET_PORT = int(os.getenv("TELNET_PORT", "2323"))
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", os.getenv("HOST", "0.0.0.0"))
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")

DB_PATH = os.path.join(BASE_DIR, "database", "events.db")
LOG_PATH = os.path.join(BASE_DIR, "honeypot-sentinel.log")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
MAX_LOG_SIZE = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
ALERT_THRESHOLD = 5
