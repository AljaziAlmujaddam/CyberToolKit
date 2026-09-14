"""CyberToolkit Version 2 — Flask application factory.

Creates the Flask app, applies safe local defaults, and registers routes.
Cybersecurity logic stays in the Version 1 modules under src/.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def create_app(test_config: dict | None = None) -> Flask:
    """Create the local web application. Bind it to localhost when running."""
    app = Flask(__name__)

    # Never commit real secrets. Use FLASK_SECRET_KEY or IPWHO_API_KEY in env.
    secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if secret:
        app.config["SECRET_KEY"] = secret

    app.config["JSON_SORT_KEYS"] = True
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
    app.config["MONITORED_DIR"] = PROJECT_ROOT / "data" / "monitored"
    app.config["INTEGRITY_DB"] = PROJECT_ROOT / "data" / "monitored_files.json"
    app.config["LOGS_DIR"] = PROJECT_ROOT / "logs"
    app.config["MAX_LOG_BYTES"] = 512 * 1024

    if test_config:
        app.config.update(test_config)

    from app.routes import bp

    app.register_blueprint(bp)
    _register_error_handlers(app)
    return app


def _register_error_handlers(app: Flask) -> None:
    """Return JSON errors for /api/ routes without exposing internals."""

    def _api_error(message: str, status: int):
        return jsonify({"error": message}), status

    @app.errorhandler(400)
    def bad_request(_error):
        if request.path.startswith("/api/"):
            return _api_error("Invalid request.", 400)
        return "Bad Request", 400

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return _api_error("Not found.", 404)
        return "Not Found", 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        if request.path.startswith("/api/"):
            return _api_error("Method not allowed.", 405)
        return "Method Not Allowed", 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        if request.path.startswith("/api/"):
            return _api_error("Request is too large.", 413)
        return "Payload Too Large", 413

    @app.errorhandler(429)
    def too_many_requests(_error):
        if request.path.startswith("/api/"):
            return _api_error("API request limit reached. Try again later.", 429)
        return "Too Many Requests", 429

    @app.errorhandler(500)
    def server_error(_error):
        if request.path.startswith("/api/"):
            return _api_error("Internal server error.", 500)
        return "Internal Server Error", 500
