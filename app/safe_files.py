"""Keep web file names inside a single allowed directory.

The browser must not be able to read or write arbitrary server paths.
"""

from __future__ import annotations

from pathlib import Path


def safe_filename(name: str | None) -> str | None:
    """Return a basename only, or None if the name is unsafe."""
    if not isinstance(name, str):
        return None
    raw = name.strip()
    if not raw or raw != Path(raw).name:
        return None
    if raw in {".", ".."}:
        return None
    if any(ord(character) < 32 for character in raw):
        return None
    if len(raw) > 255:
        return None
    return raw


def resolve_in_directory(root: Path, name: str | None) -> Path | None:
    """Resolve name under root, or None if it would leave the directory."""
    filename = safe_filename(name)
    if filename is None:
        return None

    base = root.resolve()
    candidate = (base / filename).resolve()
    if not candidate.is_relative_to(base):
        return None
    return candidate
