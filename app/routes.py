"""HTTP routes for CyberToolkit Version 2.

Serves the dashboard and the first JSON API endpoints.
Routes must not run shell commands or execute browser-supplied code.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from app.modules.password_analyzer import analyze_password

bp = Blueprint("main", __name__)

MAX_PASSWORD_LENGTH = 1024


def _api_error(message: str, status: int):
    return jsonify({"error": message}), status


@bp.get("/")
def index():
    """Dashboard with navigation, hero, tool cards, and about."""
    return render_template("index.html")


@bp.get("/api/status")
def api_status():
    """Prove that the browser can reach Flask and receive JSON."""
    return (
        jsonify(
            {
                "status": "online",
                "application": "CyberToolkit",
            }
        ),
        200,
    )


@bp.post("/api/password/analyze")
def api_password_analyze():
    """Validate JSON, then reuse the Version 1 Password Analyzer.

    The password is not stored, logged, or returned in the response.
    Other tools will get matching endpoints in a later part.
    """
    payload = request.get_json(silent=True)
    if payload is None:
        return _api_error("Request body must be valid JSON.", 400)
    if not isinstance(payload, dict):
        return _api_error("Request body must be a JSON object.", 400)
    if "password" not in payload:
        return _api_error("Missing field: password.", 400)

    password = payload["password"]
    if not isinstance(password, str):
        return _api_error("Field 'password' must be a string.", 400)
    if len(password) > MAX_PASSWORD_LENGTH:
        return _api_error("Password is too long.", 400)

    result = analyze_password(password)
    return jsonify(result), 200
