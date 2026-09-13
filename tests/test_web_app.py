#!/usr/bin/env python3
"""Tests for the Version 2 Flask dashboard and first API endpoints."""

from __future__ import annotations

import json
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
        self.assertIn("Check backend", body)
        self.assertIn("backend-status", body)
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
        self.assertIn(b'fetch("/api/status")', response.data)
        self.assertNotIn(b"eval(", response.data)
        self.assertNotIn(b"IPWHO_API_KEY", response.data)


class ApiStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_status_returns_json(self) -> None:
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        payload = response.get_json()
        self.assertEqual(payload["status"], "online")
        self.assertEqual(payload["application"], "CyberToolkit")
        self.assertNotIn("FLASK_SECRET_KEY", payload)
        self.assertNotIn("password", payload)

    def test_unknown_api_endpoint_is_json_404(self) -> None:
        response = self.client.get("/api/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json()["error"], "Not found.")

    def test_wrong_method_on_status_is_json_405(self) -> None:
        response = self.client.post("/api/status")
        self.assertEqual(response.status_code, 405)
        self.assertTrue(response.is_json)
        self.assertEqual(response.get_json()["error"], "Method not allowed.")


class PasswordApiValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_analyze_valid_password(self) -> None:
        response = self.client.post(
            "/api/password/analyze",
            data=json.dumps({"password": "ExamplePassword123!"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["strength"], "Strong")
        self.assertGreaterEqual(payload["length"], 12)
        self.assertNotIn("password", payload)
        self.assertNotIn("ExamplePassword123!", response.get_data(as_text=True))

    def test_missing_password_field(self) -> None:
        response = self.client.post(
            "/api/password/analyze",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Missing field: password.")

    def test_invalid_json(self) -> None:
        response = self.client.post(
            "/api/password/analyze",
            data="{not-json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_password_must_be_string(self) -> None:
        response = self.client.post(
            "/api/password/analyze",
            data=json.dumps({"password": 12345}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "Field 'password' must be a string.",
        )


class Version1PreservedTests(unittest.TestCase):
    def test_v1_password_helper_still_works(self) -> None:
        self.assertEqual(password_length("secret"), 6)

    def test_v1_hash_helper_still_works(self) -> None:
        digest = hash_text("Hello", "sha256")
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
