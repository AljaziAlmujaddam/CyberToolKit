#!/usr/bin/env python3
"""Tests for the Hash Calculator module."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from hash_calculator import compare_hashes, hash_file, hash_text  # noqa: E402

# Known SHA-256 of the UTF-8 bytes for "Hello"
HELLO_SHA256 = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
HELLO_LOWER_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


class HashTextTests(unittest.TestCase):
    def test_sha256_hello(self) -> None:
        self.assertEqual(hash_text("Hello", "sha256"), HELLO_SHA256)

    def test_case_change_changes_hash(self) -> None:
        self.assertEqual(hash_text("hello", "sha256"), HELLO_LOWER_SHA256)
        self.assertNotEqual(hash_text("Hello", "sha256"), hash_text("hello", "sha256"))

    def test_same_input_same_hash(self) -> None:
        self.assertEqual(hash_text("CyberToolkit", "sha256"), hash_text("CyberToolkit", "sha256"))

    def test_tiny_change_changes_hash(self) -> None:
        self.assertNotEqual(hash_text("Hello", "sha256"), hash_text("Hello!", "sha256"))

    def test_sha512_length(self) -> None:
        digest = hash_text("123456", "sha512")
        self.assertEqual(len(digest), 128)

    def test_md5_length(self) -> None:
        digest = hash_text("Hello", "md5")
        self.assertEqual(len(digest), 32)

    def test_unsupported_algorithm(self) -> None:
        with self.assertRaises(ValueError):
            hash_text("Hello", "sha1")


class HashFileTests(unittest.TestCase):
    def test_file_hash_matches_text_hash(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"Hello")
            path = handle.name
        try:
            self.assertEqual(hash_file(path, "sha256"), HELLO_SHA256)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            hash_file("/tmp/cybertoolkit-does-not-exist-xyz.bin", "sha256")

    def test_directory_is_not_hashed_as_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                hash_file(directory, "sha256")


class CompareHashTests(unittest.TestCase):
    def test_matching_hashes(self) -> None:
        self.assertTrue(compare_hashes(HELLO_SHA256, HELLO_SHA256))

    def test_matching_hashes_ignore_case(self) -> None:
        self.assertTrue(compare_hashes(HELLO_SHA256.upper(), HELLO_SHA256))

    def test_different_hashes(self) -> None:
        self.assertFalse(compare_hashes(HELLO_SHA256, HELLO_LOWER_SHA256))

    def test_empty_hash_rejected(self) -> None:
        with self.assertRaises(ValueError):
            compare_hashes("", HELLO_SHA256)


if __name__ == "__main__":
    unittest.main()
