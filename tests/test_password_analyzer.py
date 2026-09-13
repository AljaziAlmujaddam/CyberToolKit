#!/usr/bin/env python3
"""Tests for the Password Analyzer module."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from password_analyzer import (  # noqa: E402
    STRENGTH_MEDIUM,
    STRENGTH_STRONG,
    STRENGTH_VERY_WEAK,
    STRENGTH_WEAK,
    analyze_password,
    format_analysis,
    has_digit,
    has_lowercase,
    has_special,
    has_uppercase,
    password_length,
)


class PasswordLengthTests(unittest.TestCase):
    def test_length_helper(self) -> None:
        self.assertEqual(password_length(""), 0)
        self.assertEqual(password_length("abc"), 3)
        self.assertEqual(password_length("P@ssw0rd"), 8)


class CharacterClassTests(unittest.TestCase):
    def test_uppercase(self) -> None:
        self.assertTrue(has_uppercase("Abc"))
        self.assertFalse(has_uppercase("abc"))

    def test_lowercase(self) -> None:
        self.assertTrue(has_lowercase("Abc"))
        self.assertFalse(has_lowercase("ABC"))

    def test_digit(self) -> None:
        self.assertTrue(has_digit("ab3"))
        self.assertFalse(has_digit("abc"))

    def test_special(self) -> None:
        self.assertTrue(has_special("ab!"))
        self.assertFalse(has_special("abc123"))


class StrengthTests(unittest.TestCase):
    def test_empty_is_very_weak(self) -> None:
        result = analyze_password("")
        self.assertEqual(result["length"], 0)
        self.assertEqual(result["class_count"], 0)
        self.assertEqual(result["strength"], STRENGTH_VERY_WEAK)

    def test_short_password_is_very_weak(self) -> None:
        result = analyze_password("Ab1!")
        self.assertEqual(result["strength"], STRENGTH_VERY_WEAK)

    def test_letters_only_is_weak_when_long_enough(self) -> None:
        result = analyze_password("PasswordOnly")
        self.assertTrue(result["uppercase"])
        self.assertTrue(result["lowercase"])
        self.assertFalse(result["digit"])
        self.assertFalse(result["special"])
        self.assertEqual(result["strength"], STRENGTH_WEAK)

    def test_three_classes_and_length_is_medium(self) -> None:
        result = analyze_password("Password1234")
        self.assertEqual(result["class_count"], 3)
        self.assertEqual(result["strength"], STRENGTH_MEDIUM)

    def test_all_classes_and_length_is_strong(self) -> None:
        result = analyze_password("Password1234!")
        self.assertTrue(result["uppercase"])
        self.assertTrue(result["lowercase"])
        self.assertTrue(result["digit"])
        self.assertTrue(result["special"])
        self.assertEqual(result["strength"], STRENGTH_STRONG)


class ReportTests(unittest.TestCase):
    def test_format_does_not_echo_password(self) -> None:
        secret = "SuperSecret123!"
        text = format_analysis(analyze_password(secret))
        self.assertNotIn(secret, text)
        self.assertIn("Length: 15", text)
        self.assertIn("Strength: Strong", text)
        self.assertIn("not stored", text.lower())


if __name__ == "__main__":
    unittest.main()
