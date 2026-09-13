"""File Integrity Checker for Version 2 — reuses the Version 1 module."""

from app.modules import _v1  # noqa: F401

from integrity_checker import (  # noqa: E402
    add_file,
    check_all_files,
    check_file,
    list_monitored_files,
    remove_file,
)
