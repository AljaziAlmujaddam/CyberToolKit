#!/usr/bin/env python3
"""CyberToolkit — Hash Calculator (Part 2).

Hashes text and local files. Nothing is uploaded or saved automatically.
MD5 is offered only so you can compare it with SHA-256 / SHA-512.
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path

CHUNK_SIZE = 64 * 1024

ALGORITHMS = {
    "1": "sha256",
    "2": "sha512",
    "3": "md5",
}

DISPLAY_NAMES = {
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "md5": "MD5",
}

MD5_WARNING = (
    "WARNING:\n"
    "MD5 is included for educational purposes only.\n"
    "Do not use MD5 for security-critical applications."
)


def _new_hasher(algorithm: str):
    """Return a hashlib object. MD5 is marked as non-security use."""
    name = algorithm.lower()
    if name not in DISPLAY_NAMES:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return hashlib.new(name, usedforsecurity=(name != "md5"))


def hash_text(text: str, algorithm: str) -> str:
    """Return the hex digest of UTF-8 encoded text."""
    hasher = _new_hasher(algorithm)
    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


def hash_file(file_path: str | Path, algorithm: str) -> str:
    """Return the hex digest of a file, reading it in chunks (read-only)."""
    path = Path(file_path).expanduser()
    hasher = _new_hasher(algorithm)

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


def compare_hashes(hash1: str, hash2: str) -> bool:
    """Return True if the hashes match (case-insensitive, timing-safe)."""
    left = hash1.strip().lower()
    right = hash2.strip().lower()
    if not left or not right:
        raise ValueError("Both hashes must be non-empty.")
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def select_algorithm() -> str:
    """Ask the user to pick SHA-256, SHA-512, or MD5."""
    while True:
        print()
        print("Select hashing algorithm:")
        print()
        print("1. SHA-256")
        print("2. SHA-512")
        print("3. MD5")
        print()
        choice = input("Choose: ").strip()
        algorithm = ALGORITHMS.get(choice)
        if algorithm is None:
            print("Invalid choice. Enter 1, 2, or 3.")
            continue
        if algorithm == "md5":
            print()
            print(MD5_WARNING)
        return algorithm


def _print_menu() -> None:
    print()
    print("========================================")
    print("          HASH CALCULATOR")
    print("========================================")
    print()
    print("1. Hash Text")
    print("2. Hash File")
    print("3. Compare Hashes")
    print("4. Back")
    print()


def _display_input(text: str) -> str:
    """Show input in the result; keep huge pastes from flooding the terminal."""
    if len(text) <= 200:
        return text
    return text[:200] + f"... ({len(text)} characters total)"


def _run_hash_text() -> None:
    print()
    text = input("Enter text: ")
    if text == "":
        print("Text cannot be empty.")
        return

    algorithm = select_algorithm()
    digest = hash_text(text, algorithm)

    print()
    print("Hash Result")
    print("-----------")
    print(f"Algorithm: {DISPLAY_NAMES[algorithm]}")
    print(f"Input: {_display_input(text)}")
    print()
    print("Hash:")
    print(digest)


def _resolve_file_path(raw_path: str) -> Path | None:
    if not raw_path.strip():
        print("File path cannot be empty.")
        return None

    path = Path(raw_path.strip()).expanduser()

    if not path.exists():
        print(f"No file found at: {path}")
        return None
    if path.is_dir():
        print("That path is a directory. Provide a file path instead.")
        return None
    if not path.is_file():
        print("That path is not a regular file.")
        return None
    return path


def _run_hash_file() -> None:
    print()
    raw_path = input("Enter file path: ")
    path = _resolve_file_path(raw_path)
    if path is None:
        return

    algorithm = select_algorithm()

    try:
        digest = hash_file(path, algorithm)
    except PermissionError:
        print("Permission denied: the file could not be read.")
        return
    except OSError as error:
        print(f"Could not read the file: {error}")
        return

    print()
    print("File Hash")
    print("---------")
    print(f"File: {path.name}")
    print(f"Algorithm: {DISPLAY_NAMES[algorithm]}")
    print()
    print("Hash:")
    print(digest)


def _run_compare_hashes() -> None:
    print()
    first = input("Enter first hash: ").strip()
    second = input("Enter second hash: ").strip()

    if not first or not second:
        print("Both hashes are required.")
        return

    try:
        matched = compare_hashes(first, second)
    except ValueError as error:
        print(error)
        return

    print()
    if matched:
        print("✓ Hashes match.")
        print()
        print("The data is likely identical.")
    else:
        print("✗ Hashes do not match.")
        print()
        print("The data is different.")


def main() -> None:
    while True:
        _print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            _run_hash_text()
        elif choice == "2":
            _run_hash_file()
        elif choice == "3":
            _run_compare_hashes()
        elif choice == "4":
            print("Leaving Hash Calculator.")
            return
        else:
            print("Invalid choice. Enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
