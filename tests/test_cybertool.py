#!/usr/bin/env python3
"""Tests for the CyberToolkit main menu."""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

import cybertool  # noqa: E402


class MainMenuTests(unittest.TestCase):
    def test_menu_lists_all_options(self) -> None:
        buffer = io.StringIO()
        with patch("sys.stdout", buffer):
            cybertool.display_menu()
        text = buffer.getvalue()
        self.assertIn("CYBERTOOLKIT", text)
        self.assertIn("1. Password Analyzer", text)
        self.assertIn("2. Hash Calculator", text)
        self.assertIn("3. File Integrity Checker", text)
        self.assertIn("4. IP Information Tool", text)
        self.assertIn("5. Log Analyzer", text)
        self.assertIn("6. Exit", text)

    @patch("cybertool.pause_for_menu")
    @patch("cybertool.password_analyzer.main")
    def test_choice_opens_password_analyzer(self, mock_main, _pause) -> None:
        self.assertTrue(cybertool.handle_choice("1"))
        mock_main.assert_called_once()

    @patch("cybertool.pause_for_menu")
    @patch("cybertool.hash_calculator.main")
    def test_choice_opens_hash_calculator(self, mock_main, _pause) -> None:
        self.assertTrue(cybertool.handle_choice("2"))
        mock_main.assert_called_once()

    @patch("cybertool.pause_for_menu")
    @patch("cybertool.integrity_checker.main")
    def test_choice_opens_integrity_checker(self, mock_main, _pause) -> None:
        self.assertTrue(cybertool.handle_choice("3"))
        mock_main.assert_called_once()

    @patch("cybertool.pause_for_menu")
    @patch("cybertool.ip_information.main")
    def test_choice_opens_ip_information(self, mock_main, _pause) -> None:
        self.assertTrue(cybertool.handle_choice("4"))
        mock_main.assert_called_once()

    @patch("cybertool.pause_for_menu")
    @patch("cybertool.log_analyzer.main")
    def test_choice_opens_log_analyzer(self, mock_main, _pause) -> None:
        self.assertTrue(cybertool.handle_choice("5"))
        mock_main.assert_called_once()

    def test_invalid_text_input(self) -> None:
        buffer = io.StringIO()
        with patch("sys.stdout", buffer):
            result = cybertool.handle_choice("abc")
        self.assertTrue(result)
        self.assertIn("Invalid input.", buffer.getvalue())
        self.assertIn("Please enter a number.", buffer.getvalue())

    def test_empty_input(self) -> None:
        buffer = io.StringIO()
        with patch("sys.stdout", buffer):
            result = cybertool.handle_choice("   ")
        self.assertTrue(result)
        self.assertIn("Invalid input.", buffer.getvalue())

    def test_invalid_menu_number(self) -> None:
        buffer = io.StringIO()
        with patch("sys.stdout", buffer):
            result = cybertool.handle_choice("9")
        self.assertTrue(result)
        self.assertIn("Invalid option.", buffer.getvalue())
        self.assertIn("between 1 and 6", buffer.getvalue())

    def test_exit(self) -> None:
        buffer = io.StringIO()
        with patch("sys.stdout", buffer):
            result = cybertool.handle_choice("6")
        self.assertFalse(result)
        self.assertIn("Thank you for using CyberToolkit.", buffer.getvalue())
        self.assertIn("Goodbye!", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
