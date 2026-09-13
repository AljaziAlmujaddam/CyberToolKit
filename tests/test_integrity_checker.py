#!/usr/bin/env python3
"""Tests for the File Integrity Checker module."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from hash_calculator import hash_text  # noqa: E402
from integrity_checker import (  # noqa: E402
    STATUS_ADDED,
    STATUS_MISSING,
    STATUS_MODIFIED,
    STATUS_NOT_REGISTERED,
    STATUS_REMOVED,
    STATUS_UNCHANGED,
    STATUS_UPDATED,
    add_file,
    calculate_file_hash,
    check_all_files,
    check_file,
    list_monitored_files,
    load_monitored_files,
    remove_file,
)


HELLO = "Hello CyberToolkit"
HELLO_CHANGED = "Hello CyberToolkit!"
HELLO_SHA256 = hash_text(HELLO, "sha256")
HELLO_CHANGED_SHA256 = hash_text(HELLO_CHANGED, "sha256")


class IntegrityCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.database = self.root / "monitored_files.json"
        self.sample = self.root / "test_file.txt"
        self.sample.write_text(HELLO, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_calculate_file_hash_matches_text_hash(self) -> None:
        self.assertEqual(calculate_file_hash(self.sample), HELLO_SHA256)

    def test_add_file_stores_path_and_hash_not_contents(self) -> None:
        result = add_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_ADDED)
        self.assertEqual(result["sha256"], HELLO_SHA256)

        payload = json.loads(self.database.read_text(encoding="utf-8"))
        self.assertEqual(payload["files"][0]["sha256"], HELLO_SHA256)
        self.assertEqual(payload["files"][0]["path"], str(self.sample.resolve()))
        dumped = self.database.read_text(encoding="utf-8")
        self.assertNotIn(HELLO, dumped)

    def test_check_unchanged_file(self) -> None:
        add_file(self.sample, self.database)
        result = check_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_UNCHANGED)
        self.assertEqual(result["original_hash"], HELLO_SHA256)
        self.assertEqual(result["current_hash"], HELLO_SHA256)

    def test_check_modified_file(self) -> None:
        add_file(self.sample, self.database)
        self.sample.write_text(HELLO_CHANGED, encoding="utf-8")
        result = check_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_MODIFIED)
        self.assertEqual(result["original_hash"], HELLO_SHA256)
        self.assertEqual(result["current_hash"], HELLO_CHANGED_SHA256)

    def test_check_missing_registered_file(self) -> None:
        add_file(self.sample, self.database)
        self.sample.unlink()
        result = check_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_MISSING)
        self.assertEqual(result["original_hash"], HELLO_SHA256)
        self.assertIsNone(result["current_hash"])

    def test_check_unregistered_existing_file(self) -> None:
        result = check_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_NOT_REGISTERED)

    def test_add_missing_file(self) -> None:
        missing = self.root / "does-not-exist.txt"
        result = add_file(missing, self.database)
        self.assertEqual(result["status"], STATUS_MISSING)

    def test_add_directory_rejected(self) -> None:
        result = add_file(self.root, self.database)
        self.assertEqual(result["status"], "invalid")

    def test_empty_path_rejected(self) -> None:
        result = add_file("   ", self.database)
        self.assertEqual(result["status"], "invalid")

    def test_readd_updates_reference_hash(self) -> None:
        add_file(self.sample, self.database)
        self.sample.write_text(HELLO_CHANGED, encoding="utf-8")
        result = add_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_UPDATED)
        self.assertEqual(result["sha256"], HELLO_CHANGED_SHA256)
        self.assertEqual(len(load_monitored_files(self.database)), 1)

    def test_multiple_files_and_check_all(self) -> None:
        second = self.root / "config.txt"
        second.write_text("ok", encoding="utf-8")
        add_file(self.sample, self.database)
        add_file(second, self.database)
        self.sample.write_text(HELLO_CHANGED, encoding="utf-8")

        listed = list_monitored_files(self.database)
        self.assertEqual(len(listed), 2)

        results = check_all_files(self.database)
        statuses = {item["name"]: item["status"] for item in results}
        self.assertEqual(statuses["test_file.txt"], STATUS_MODIFIED)
        self.assertEqual(statuses["config.txt"], STATUS_UNCHANGED)

    def test_remove_file(self) -> None:
        add_file(self.sample, self.database)
        result = remove_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_REMOVED)
        self.assertEqual(load_monitored_files(self.database), [])
        self.assertTrue(self.sample.exists())

    def test_remove_unregistered_file(self) -> None:
        result = remove_file(self.sample, self.database)
        self.assertEqual(result["status"], STATUS_NOT_REGISTERED)

    def test_load_missing_database(self) -> None:
        self.assertEqual(load_monitored_files(self.root / "none.json"), [])


if __name__ == "__main__":
    unittest.main()
