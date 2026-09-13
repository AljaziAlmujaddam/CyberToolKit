"""HTTP routes for CyberToolkit Version 2.

Serves the dashboard. Tool APIs come in a later part.
Routes must not run shell commands or execute browser-supplied code.
"""

from __future__ import annotations

from flask import Blueprint, render_template

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    """Dashboard with navigation, hero, tool cards, and about."""
    return render_template("index.html")
