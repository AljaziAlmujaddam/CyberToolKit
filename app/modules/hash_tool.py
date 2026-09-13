"""Hash Calculator for Version 2 — reuses the Version 1 module."""

from app.modules import _v1  # noqa: F401

from hash_calculator import (  # noqa: E402
    compare_hashes,
    hash_file,
    hash_text,
)
