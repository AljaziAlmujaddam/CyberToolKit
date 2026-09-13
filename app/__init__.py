"""CyberToolkit Version 2 — Flask application factory.

The web layer only serves pages and (later) routes requests.
Cybersecurity logic stays in the Version 1 modules under src/.
"""

from __future__ import annotations

import os

from flask import Flask


def create_app() -> Flask:
    """Create the local web application. Bind it to localhost when running."""
    app = Flask(__name__)

    # Never commit real secrets. Local Part 1 does not use sessions.
    secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if secret:
        app.config["SECRET_KEY"] = secret

    app.config["JSON_SORT_KEYS"] = True

    from app.routes import bp

    app.register_blueprint(bp)
    return app
