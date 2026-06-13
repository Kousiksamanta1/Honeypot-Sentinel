"""Cached AbuseIPDB v2 lookups."""

import threading

import requests

from config import ABUSEIPDB_API_KEY


_cache = {}
_cache_lock = threading.Lock()


def check_ip(ip_address):
    with _cache_lock:
        if ip_address in _cache:
            return dict(_cache[ip_address])

    default = {
        "abuseConfidenceScore": 0,
        "isPublic": False,
        "usageType": "",
        "isTor": False,
    }
    if not ABUSEIPDB_API_KEY:
        with _cache_lock:
            _cache[ip_address] = dict(default)
        return dict(default)

    result = default
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            headers={
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY,
            },
            timeout=5,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        result = {
            "abuseConfidenceScore": int(data.get("abuseConfidenceScore", 0) or 0),
            "isPublic": bool(data.get("isPublic", False)),
            "usageType": data.get("usageType") or "",
            "isTor": bool(data.get("isTor", False)),
        }
    except (requests.RequestException, ValueError, TypeError):
        result = default

    with _cache_lock:
        _cache[ip_address] = dict(result)
    return result
