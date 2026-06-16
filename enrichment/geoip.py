"""Cached and rate-limited geolocation lookups."""

import ipaddress
import threading
import time

import requests

from config import GEOIP_LOOKUP_URL, GEOIP_RATE_INTERVAL


_cache = {}
_cache_lock = threading.Lock()
_request_lock = threading.Lock()
_last_request = 0.0
_RATE_INTERVAL = GEOIP_RATE_INTERVAL
_IP_API_FIELDS = (
    "status,country,countryCode,region,regionName,city,zip,"
    "lat,lon,timezone,isp,org,as"
)


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


def _request_params(url):
    if "ip-api.com" in url:
        return {"fields": _IP_API_FIELDS}
    return None


def _normalize_payload(payload):
    if payload.get("status") == "success":
        country_code = payload.get("countryCode", "")
        return {
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

    if payload.get("error"):
        return {}

    country_code = payload.get("country_code") or payload.get("country") or ""
    organization = payload.get("org") or ""
    return {
        "country": payload.get("country_name") or payload.get("country") or "",
        "country_code": country_code,
        "region": payload.get("region") or payload.get("regionName") or "",
        "city": payload.get("city", ""),
        "zip_code": payload.get("postal") or payload.get("zip") or "",
        "latitude": payload.get("latitude") or payload.get("lat"),
        "longitude": payload.get("longitude") or payload.get("lon"),
        "timezone": payload.get("timezone", ""),
        "isp": payload.get("network") or organization,
        "org": organization,
        "as": payload.get("asn") or payload.get("as") or "",
        "country_flag": get_flag_emoji(country_code),
    }


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
        url = GEOIP_LOOKUP_URL.format(ip_address=ip_address)
        with _request_lock:
            elapsed = time.monotonic() - _last_request
            if elapsed < _RATE_INTERVAL:
                time.sleep(_RATE_INTERVAL - elapsed)
            response = requests.get(
                url,
                params=_request_params(url),
                timeout=5,
            )
            _last_request = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        result = _normalize_payload(payload)
    except (requests.RequestException, ValueError, TypeError):
        result = {}

    with _cache_lock:
        _cache[ip_address] = dict(result)
    return result
