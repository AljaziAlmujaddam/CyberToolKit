"""Log Analyzer for Version 2 — reuses the Version 1 module."""

from app.modules import _v1  # noqa: F401

from log_analyzer import (  # noqa: E402
    FAILED_LOGIN_THRESHOLD,
    analyze_log_file,
    format_report,
    load_log_file,
    search_logs,
)
