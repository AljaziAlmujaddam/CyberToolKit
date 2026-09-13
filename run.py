#!/usr/bin/env python3
"""Start the CyberToolkit Version 2 development server (localhost only)."""

from __future__ import annotations

from app import create_app

app = create_app()


if __name__ == "__main__":
    # 127.0.0.1 keeps the server on this computer during development.
    app.run(host="127.0.0.1", port=5000, debug=True)
