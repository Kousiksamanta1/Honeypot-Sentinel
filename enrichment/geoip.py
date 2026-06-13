"""Cached and rate-limited geolocation lookups."""

import ipaddress
import threading
import time

import requests


_cache = {}
_cache_lock = threading.Lock()
_request_lock = threading.Lock()
_last_request = 0.0
_RATE_INTERVAL = 1.4


def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(
        chr(0x1F1E6 + ord(character) - ord("A"))
        for character in country_code.upper()
    )


def _is_public_ip(ip_address):
    try:
        return ipaddress.ip_address(ip_address).is_global
    except ValueError:
        return False


def lookup_ip(ip_address):
    with _cache_lock:
        if ip_address in _cache:
            return dict(_cache[ip_address])

    if not _is_public_ip(ip_address):
        with _cache_lock:
            _cache[ip_address] = {}
        return {}

    result = {}
    try:
        global _last_request
        with _request_lock:
            elapsed = time.monotonic() - _last_request
            if elapsed < _RATE_INTERVAL:
                time.sleep(_RATE_INTERVAL - elapsed)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                params={
                    "fields": (
                        "status,country,countryCode,region,regionName,city,zip,"
                        "lat,lon,timezone,isp,org,as"
                    )
                },
                timeout=5,
            )
            _last_request = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") == "success":
            country_code = payload.get("countryCode", "")
            result = {
                "country": payload.get("country", ""),
                "country_code": country_code,
                "region": payload.get("regionName", ""),
                "city": payload.get("city", ""),
                "zip_code": payload.get("zip", ""),
                "latitude": payload.get("lat"),
                "longitude": payload.get("lon"),
                "timezone": payload.get("timezone", ""),
                "isp": payload.get("isp", ""),
                "org": payload.get("org", ""),
                "as": payload.get("as", ""),
                "country_flag": get_flag_emoji(country_code),
            }
    except (requests.RequestException, ValueError, TypeError):
        result = {}

    with _cache_lock:
        _cache[ip_address] = dict(result)
    return result
