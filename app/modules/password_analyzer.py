"""Password Analyzer for Version 2 — reuses the Version 1 module."""

from app.modules import _v1  # noqa: F401

from password_analyzer import (  # noqa: E402
    analyze_password,
    classify_strength,
    format_analysis,
    password_length,
)
