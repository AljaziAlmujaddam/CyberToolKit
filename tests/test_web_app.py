#!/usr/bin/env python3
"""Tests for the Version 2 Flask dashboard."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.modules.hash_tool import hash_text  # noqa: E402
from app.modules.password_analyzer import password_length  # noqa: E402


class WebHomepageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_flask_homepage_loads(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("CyberToolkit", body)
        self.assertIn("Password Analyzer", body)
        self.assertIn("Hash Calculator", body)
        self.assertIn("File Integrity Checker", body)
        self.assertIn("IP Information", body)
        self.assertIn("Log Analyzer", body)
        self.assertIn("Explore Tools", body)
        self.assertIn('href="#home"', body)
        self.assertIn('href="#tools"', body)
        self.assertIn('href="#about"', body)
        self.assertIn("css/style.css", body)
        self.assertIn("js/app.js", body)
        self.assertNotIn("IPWHO_API_KEY", body)
        self.assertNotIn("FLASK_SECRET_KEY", body)

    def test_stylesheet_loads(self) -> None:
        response = self.client.get("/static/css/style.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"--accent", response.data)
        self.assertIn(b"tools-grid", response.data)
        self.assertIn(b"@media", response.data)

    def test_javascript_loads(self) -> None:
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"data-tool", response.data)
        self.assertIn(b"explore-tools", response.data)
        self.assertNotIn(b"eval(", response.data)
        self.assertNotIn(b"IPWHO_API_KEY", response.data)


class Version1PreservedTests(unittest.TestCase):
    def test_v1_password_helper_still_works(self) -> None:
        self.assertEqual(password_length("secret"), 6)

    def test_v1_hash_helper_still_works(self) -> None:
        digest = hash_text("Hello", "sha256")
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
