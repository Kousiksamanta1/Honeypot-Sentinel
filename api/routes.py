"""Dashboard and JSON API routes."""

from flask import Blueprint, Response, jsonify, render_template, request

from database import models


api_blueprint = Blueprint("api", __name__)


def _integer_arg(name, default, minimum=1, maximum=1000):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


@api_blueprint.get("/")
def dashboard():
    return render_template("index.html")


@api_blueprint.get("/favicon.ico")
def favicon():
    return Response(status=204)


@api_blueprint.get("/api/events")
def events():
    limit = _integer_arg("limit", 50)
    service = request.args.get("service", "").strip()
    country = request.args.get("country", "").strip()
    return jsonify(
        models.get_all_events(
            limit=limit,
            service=service or None,
            country=country or None,
        )
    )


@api_blueprint.get("/api/stats")
def stats():
    return jsonify(models.get_stats())


@api_blueprint.get("/api/attackers")
def attackers():
    return jsonify(models.get_top_attackers(limit=20))


@api_blueprint.get("/api/map")
def attack_map():
    return jsonify(models.get_map_data())


@api_blueprint.get("/api/alerts")
def alerts():
    return jsonify(models.get_alerts(limit=20))


@api_blueprint.get("/api/locations")
def locations():
    stats_data = models.get_stats()
    countries = models.get_location_breakdown()
    return jsonify(
        {
            "countries": countries,
            "top_cities": models.get_top_cities(limit=20),
            "total_countries": len(countries),
            "most_attacked_from": (
                countries[0]["country"] if countries else "N/A"
            ),
            "most_active_region": (
                stats_data["attacks_by_region"][0]["region"]
                if stats_data["attacks_by_region"]
                else "N/A"
            ),
            "most_active_timezone": (
                stats_data["attacks_by_timezone"][0]["timezone"]
                if stats_data["attacks_by_timezone"]
                else "N/A"
            ),
        }
    )


@api_blueprint.get("/api/attacker/<ip_address>")
def attacker(ip_address):
    profile = models.get_attacker_profile(ip_address)
    if profile is None:
        return jsonify({"error": "Attacker profile not found"}), 404
    profile["events"] = models.get_events_by_ip(ip_address, limit=10)
    return jsonify(profile)
