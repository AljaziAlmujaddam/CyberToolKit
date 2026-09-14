#!/usr/bin/env python3
"""Tests for the Version 2 Flask dashboard and first API endpoints."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.modules.hash_tool import hash_text  # noqa: E402
from app.modules.password_analyzer import password_length  # noqa: E402
from app.safe_files import resolve_in_directory, safe_filename  # noqa: E402


def _post_json(client, path: str, payload):
    return client.post(
        path,
        data=json.dumps(payload),
        content_type="application/json",
    )


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
        self.assertIn("Analyze Password", body)
        self.assertIn("password-input", body)
        self.assertIn("hash-algorithm", body)
        self.assertIn("SHA-256", body)
        self.assertIn("SHA-512", body)
        self.assertIn("MD5", body)
        self.assertIn("Register File", body)
        self.assertIn("Check Integrity", body)
        self.assertIn("Check All Files", body)
        self.assertIn("Analyze IP", body)
        self.assertIn("integrity-file", body)
        self.assertIn("ip-input", body)
        self.assertIn("Analyze Log", body)
        self.assertIn("log-file", body)
        self.assertIn("log-keyword", body)
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
        self.assertIn(b'fetch("/api/password/analyze"', response.data)
        self.assertIn(b'fetch("/api/hash/calculate"', response.data)
        self.assertIn(b'fetch("/api/integrity/register"', response.data)
        self.assertIn(b'fetch("/api/ip/analyze"', response.data)
        self.assertIn(b'fetch("/api/log/analyze"', response.data)
        self.assertIn(b'fetch("/api/log/search"', response.data)
        self.assertIn(b"textContent", response.data)
        self.assertNotIn(b"eval(", response.data)
        self.assertNotIn(b"IPWHO_API_KEY", response.data)
        self.assertNotIn(b"createHash", response.data)


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


class PasswordApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_strong_password(self) -> None:
        sample = "ExamplePassword123!"
        response = _post_json(
            self.client, "/api/password/analyze", {"password": sample}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["strength"], "Strong")
        self.assertTrue(payload["uppercase"])
        self.assertTrue(payload["lowercase"])
        self.assertTrue(payload["digit"])
        self.assertTrue(payload["special"])
        self.assertNotIn("password", payload)
        self.assertNotIn(sample, response.get_data(as_text=True))

    def test_very_weak_password(self) -> None:
        response = _post_json(
            self.client, "/api/password/analyze", {"password": "aaaa"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["strength"], "Very Weak")

    def test_weak_password(self) -> None:
        response = _post_json(
            self.client, "/api/password/analyze", {"password": "Abcdefghij"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["strength"], "Weak")

    def test_medium_password(self) -> None:
        response = _post_json(
            self.client, "/api/password/analyze", {"password": "Abcdefghijk1"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["strength"], "Medium")

    def test_unicode_password(self) -> None:
        response = _post_json(
            self.client, "/api/password/analyze", {"password": "密码Abcdef1!"}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertGreater(payload["length"], 0)
        self.assertNotIn("密码Abcdef1!", response.get_data(as_text=True))

    def test_script_input_is_data_not_code(self) -> None:
        payload_in = {"password": '<script>alert("test")</script>A1!aaaa'}
        response = _post_json(self.client, "/api/password/analyze", payload_in)
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertNotIn("<script>", body)
        self.assertNotIn("alert(", body)

    def test_empty_password(self) -> None:
        response = _post_json(
            self.client, "/api/password/analyze", {"password": ""}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Password is required.")

    def test_missing_password_field(self) -> None:
        response = _post_json(self.client, "/api/password/analyze", {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Password is required.")

    def test_invalid_json(self) -> None:
        response = self.client.post(
            "/api/password/analyze",
            data="{not-json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_password_must_be_string(self) -> None:
        response = _post_json(
            self.client, "/api/password/analyze", {"password": 12345}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "Field 'password' must be a string.",
        )


class HashApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_sha256(self) -> None:
        text = "Hello CyberToolkit"
        response = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": text, "algorithm": "sha256"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["algorithm"], "SHA-256")
        self.assertEqual(payload["hash"], hashlib.sha256(text.encode()).hexdigest())
        self.assertNotIn("warning", payload)
        self.assertNotIn(text, response.get_data(as_text=True))

    def test_sha512(self) -> None:
        text = "Hello CyberToolkit"
        response = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": text, "algorithm": "SHA-512"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["algorithm"], "SHA-512")
        self.assertEqual(len(payload["hash"]), 128)

    def test_md5_includes_warning(self) -> None:
        response = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": "Hello CyberToolkit", "algorithm": "md5"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["algorithm"], "MD5")
        self.assertEqual(len(payload["hash"]), 32)
        self.assertIn("educational", payload["warning"].lower())

    def test_same_input_same_hash(self) -> None:
        payload = {"text": "repeat-me", "algorithm": "sha256"}
        first = _post_json(self.client, "/api/hash/calculate", payload).get_json()
        second = _post_json(self.client, "/api/hash/calculate", payload).get_json()
        self.assertEqual(first["hash"], second["hash"])

    def test_different_input_different_hash(self) -> None:
        first = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": "alpha", "algorithm": "sha256"},
        ).get_json()
        second = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": "beta", "algorithm": "sha256"},
        ).get_json()
        self.assertNotEqual(first["hash"], second["hash"])

    def test_invalid_algorithm_is_rejected(self) -> None:
        response = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": "hello", "algorithm": "something_random"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported algorithm", response.get_json()["error"])

    def test_empty_text(self) -> None:
        response = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": "", "algorithm": "sha256"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Text is required.")

    def test_missing_algorithm(self) -> None:
        response = _post_json(
            self.client, "/api/hash/calculate", {"text": "hello"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Algorithm is required.")

    def test_sql_looking_text_is_hashed(self) -> None:
        text = "'; DROP TABLE users; --"
        response = _post_json(
            self.client,
            "/api/hash/calculate",
            {"text": text, "algorithm": "sha256"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertNotIn("DROP TABLE", body)
        self.assertEqual(
            response.get_json()["hash"],
            hashlib.sha256(text.encode()).hexdigest(),
        )


class PathSafetyTests(unittest.TestCase):
    def test_rejects_parent_and_separators(self) -> None:
        self.assertIsNone(safe_filename(".."))
        self.assertIsNone(safe_filename("../secret.txt"))
        self.assertIsNone(safe_filename("../../notes.txt"))
        self.assertEqual(safe_filename("notes.txt"), "notes.txt")

    def test_resolve_stays_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            inside = resolve_in_directory(root, "ok.txt")
            self.assertIsNotNone(inside)
            self.assertTrue(inside.is_relative_to(root.resolve()))
            self.assertIsNone(resolve_in_directory(root, ".."))
            self.assertIsNone(resolve_in_directory(root, "/etc/passwd"))


class IntegrityApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        monitored = root / "monitored"
        monitored.mkdir()
        self.monitored = monitored
        self.client = create_app(
            {
                "TESTING": True,
                "MONITORED_DIR": monitored,
                "INTEGRITY_DB": root / "monitored_files.json",
            }
        ).test_client()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _upload(self, path: str, filename: str, content: bytes):
        return self.client.post(
            path,
            data={"file": (BytesIO(content), filename)},
            content_type="multipart/form-data",
        )

    def test_register_and_unchanged_check(self) -> None:
        sample = b"Hello CyberToolkit"
        response = self._upload("/api/integrity/register", "notes.txt", sample)
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "added")
        self.assertEqual(payload["name"], "notes.txt")
        self.assertNotIn("path", payload)
        self.assertNotIn(sample.decode(), response.get_data(as_text=True))

        listed = self.client.get("/api/integrity/files")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.get_json()["files"][0]["name"], "notes.txt")

        check = _post_json(
            self.client, "/api/integrity/check", {"filename": "notes.txt"}
        )
        self.assertEqual(check.status_code, 200)
        self.assertEqual(check.get_json()["status"], "unchanged")
        self.assertEqual(check.get_json()["label"], "Integrity Verified")

    def test_duplicate_register_updates_hash(self) -> None:
        self._upload("/api/integrity/register", "notes.txt", b"one")
        response = self._upload("/api/integrity/register", "notes.txt", b"two")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "updated")

    def test_modified_file(self) -> None:
        self._upload("/api/integrity/register", "notes.txt", b"original")
        check = self._upload("/api/integrity/check", "notes.txt", b"changed")
        self.assertEqual(check.status_code, 200)
        self.assertEqual(check.get_json()["status"], "modified")
        self.assertEqual(check.get_json()["label"], "File Modified")

    def test_missing_file(self) -> None:
        self._upload("/api/integrity/register", "notes.txt", b"keep")
        (self.monitored / "notes.txt").unlink()
        check = _post_json(
            self.client, "/api/integrity/check", {"filename": "notes.txt"}
        )
        self.assertEqual(check.status_code, 200)
        self.assertEqual(check.get_json()["status"], "missing")

    def test_unregistered_file(self) -> None:
        check = self._upload("/api/integrity/check", "other.txt", b"hello")
        self.assertEqual(check.status_code, 200)
        self.assertEqual(check.get_json()["status"], "not_registered")

    def test_no_file_selected(self) -> None:
        response = self.client.post("/api/integrity/register")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "No file selected.")

    def test_path_traversal_rejected(self) -> None:
        response = _post_json(
            self.client, "/api/integrity/check", {"filename": "../secret.txt"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Invalid file path.")

        absolute = _post_json(
            self.client, "/api/integrity/check", {"filename": "/etc/passwd"}
        )
        self.assertEqual(absolute.status_code, 400)

    def test_check_all_multiple_files(self) -> None:
        self._upload("/api/integrity/register", "a.txt", b"aaa")
        self._upload("/api/integrity/register", "b.txt", b"bbb")
        (self.monitored / "a.txt").write_bytes(b"changed")
        response = self.client.post("/api/integrity/check-all")
        self.assertEqual(response.status_code, 200)
        statuses = {item["name"]: item["status"] for item in response.get_json()["files"]}
        self.assertEqual(statuses["a.txt"], "modified")
        self.assertEqual(statuses["b.txt"], "unchanged")


class IpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app({"TESTING": True}).test_client()

    def test_private_ip_is_not_looked_up(self) -> None:
        with patch("app.routes.get_ip_information") as mock_lookup:
            mock_lookup.return_value = {
                "ip": "192.168.1.1",
                "version": "IPv4",
                "type": "Private",
                "hostname": None,
                "country": None,
                "region": None,
                "city": None,
                "isp": None,
                "org": None,
                "asn": None,
                "timezone": None,
                "error": "no_info",
            }
            response = _post_json(
                self.client, "/api/ip/analyze", {"ip": "192.168.1.1"}
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["type"], "Private")
        self.assertIn("not sent", payload["note"])
        self.assertNotIn("IPWHO_API_KEY", response.get_data(as_text=True))

    def test_loopback(self) -> None:
        response = _post_json(self.client, "/api/ip/analyze", {"ip": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["type"], "Loopback")
        self.assertEqual(response.get_json()["version"], "IPv4")

    def test_ipv6_classification(self) -> None:
        response = _post_json(self.client, "/api/ip/analyze", {"ip": "::1"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["version"], "IPv6")
        self.assertEqual(payload["type"], "Loopback")

    def test_invalid_and_empty(self) -> None:
        invalid = _post_json(self.client, "/api/ip/analyze", {"ip": "999.999.999.999"})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.get_json()["error"], "Invalid IP address.")
        empty = _post_json(self.client, "/api/ip/analyze", {"ip": ""})
        self.assertEqual(empty.status_code, 400)
        missing = _post_json(self.client, "/api/ip/analyze", {})
        self.assertEqual(missing.status_code, 400)

    def test_public_ip_uses_module(self) -> None:
        fake = {
            "ip": "8.8.8.8",
            "version": "IPv4",
            "type": "Public",
            "hostname": "dns.google",
            "country": "United States",
            "region": "California",
            "city": "Mountain View",
            "isp": "Google",
            "org": "Google LLC",
            "asn": "AS15169",
            "timezone": "America/Los_Angeles",
            "error": None,
        }
        with patch("app.routes.get_ip_information", return_value=fake):
            response = _post_json(self.client, "/api/ip/analyze", {"ip": "8.8.8.8"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["country"], "United States")
        self.assertIn("ipwho.is", payload["privacy_note"])

    def test_timeout_and_unreachable(self) -> None:
        timeout = {
            "ip": "8.8.8.8",
            "version": "IPv4",
            "type": "Public",
            "hostname": None,
            "country": None,
            "region": None,
            "city": None,
            "isp": None,
            "org": None,
            "asn": None,
            "timezone": None,
            "error": "timeout",
        }
        with patch("app.routes.get_ip_information", return_value=timeout):
            response = _post_json(self.client, "/api/ip/analyze", {"ip": "8.8.8.8"})
        self.assertEqual(response.status_code, 504)
        self.assertIn("timed out", response.get_json()["error"])

        timeout["error"] = "unreachable"
        with patch("app.routes.get_ip_information", return_value=timeout):
            response = _post_json(self.client, "/api/ip/analyze", {"ip": "1.1.1.1"})
        self.assertEqual(response.status_code, 502)


class LogApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app({"TESTING": True}).test_client()

    def test_list_includes_sample_log(self) -> None:
        response = self.client.get("/api/log/files")
        self.assertEqual(response.status_code, 200)
        self.assertIn("sample.log", response.get_json()["files"])

    def test_analyze_sample_log(self) -> None:
        response = _post_json(
            self.client, "/api/log/analyze", {"filename": "sample.log"}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertGreater(payload["total_entries"], 0)
        self.assertGreater(payload["info"], 0)
        self.assertGreater(payload["warnings"], 0)
        self.assertGreater(payload["errors"], 0)
        self.assertGreater(payload["failed_logins"], 0)
        self.assertGreater(payload["successful_logins"], 0)
        self.assertIn("192.168.1.20", payload["ip_addresses"])
        suspicious = {item["ip"] for item in payload["suspicious_activity"]}
        self.assertIn("192.168.1.20", suspicious)
        self.assertNotIn("path", payload)
        body = response.get_data(as_text=True)
        self.assertNotIn("/Users/", body)
        self.assertIn("potentially suspicious", payload["note"].lower())

    def test_empty_log_upload(self) -> None:
        response = self.client.post(
            "/api/log/analyze",
            data={"file": (BytesIO(b""), "empty.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["total_entries"], 0)

    def test_search_is_case_insensitive(self) -> None:
        response = _post_json(
            self.client,
            "/api/log/search",
            {"filename": "sample.log", "keyword": "FAILED"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertGreater(payload["match_count"], 0)
        self.assertTrue(any("ailed" in line for line in payload["matches"]))

    def test_search_requires_keyword(self) -> None:
        response = _post_json(
            self.client,
            "/api/log/search",
            {"filename": "sample.log", "keyword": "  "},
        )
        self.assertEqual(response.status_code, 400)

    def test_no_file_selected(self) -> None:
        response = self.client.post("/api/log/analyze")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "No file selected.")

    def test_path_traversal_rejected(self) -> None:
        response = _post_json(
            self.client, "/api/log/analyze", {"filename": "../src/cybertool.py"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Invalid file path.")

    def test_binary_upload_rejected(self) -> None:
        response = self.client.post(
            "/api/log/analyze",
            data={"file": (BytesIO(b"\x00\x01binary"), "malware.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_oversized_upload_rejected(self) -> None:
        small = create_app({"TESTING": True, "MAX_LOG_BYTES": 8}).test_client()
        response = small.post(
            "/api/log/analyze",
            data={"file": (BytesIO(b"0123456789"), "big.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)


class Version1PreservedTests(unittest.TestCase):
    def test_v1_password_helper_still_works(self) -> None:
        self.assertEqual(password_length("secret"), 6)

    def test_v1_hash_helper_still_works(self) -> None:
        digest = hash_text("Hello", "sha256")
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
