"""CyberToolkit Version 2 — Flask application factory.

Creates the Flask app, applies safe local defaults, and registers routes.
Cybersecurity logic stays in the Version 1 modules under src/.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request


def create_app() -> Flask:
    """Create the local web application. Bind it to localhost when running."""
    app = Flask(__name__)

    # Never commit real secrets. Sessions are not required for Part 3.
    secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if secret:
        app.config["SECRET_KEY"] = secret

    app.config["JSON_SORT_KEYS"] = True
    # Reject oversized bodies instead of reading them into memory.
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

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

    @app.errorhandler(500)
    def server_error(_error):
        if request.path.startswith("/api/"):
            return _api_error("Internal server error.", 500)
        return "Internal Server Error", 500
