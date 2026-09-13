#!/usr/bin/env python3
"""Tests for the IP Information Tool module."""

from __future__ import annotations

import io
import json
import socket
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from ip_information import (  # noqa: E402
    format_ip_information,
    get_ip_information,
    get_ip_version,
    identify_ip_type,
    reverse_dns_lookup,
    save_report,
    validate_ip,
)


class ValidationTests(unittest.TestCase):
    def test_valid_ipv4(self) -> None:
        self.assertTrue(validate_ip("8.8.8.8"))
        self.assertTrue(validate_ip(" 1.1.1.1 "))

    def test_valid_ipv6(self) -> None:
        self.assertTrue(validate_ip("2001:4860:4860::8888"))

    def test_invalid_ip(self) -> None:
        self.assertFalse(validate_ip("999.999.999.999"))
        self.assertFalse(validate_ip(""))
        self.assertFalse(validate_ip("not-an-ip"))

    def test_versions(self) -> None:
        self.assertEqual(get_ip_version("8.8.8.8"), "IPv4")
        self.assertEqual(get_ip_version("2001:4860:4860::8888"), "IPv6")
        self.assertIsNone(get_ip_version("999.999.999.999"))

    def test_types(self) -> None:
        self.assertEqual(identify_ip_type("8.8.8.8"), "Public")
        self.assertEqual(identify_ip_type("1.1.1.1"), "Public")
        self.assertEqual(identify_ip_type("192.168.1.1"), "Private")
        self.assertEqual(identify_ip_type("10.0.0.5"), "Private")
        self.assertEqual(identify_ip_type("127.0.0.1"), "Loopback")
        self.assertEqual(identify_ip_type("0.0.0.0"), "Reserved")
        self.assertEqual(identify_ip_type("999.999.999.999"), "Invalid")


class ReverseDnsTests(unittest.TestCase):
    @patch("ip_information.socket.gethostbyaddr")
    def test_hostname_found(self, mock_lookup: MagicMock) -> None:
        mock_lookup.return_value = ("dns.google", [], ["8.8.8.8"])
        self.assertEqual(reverse_dns_lookup("8.8.8.8"), "dns.google")

    @patch("ip_information.socket.gethostbyaddr")
    def test_hostname_missing_is_normal(self, mock_lookup: MagicMock) -> None:
        mock_lookup.side_effect = socket.herror("not found")
        self.assertIsNone(reverse_dns_lookup("8.8.8.8"))

    def test_invalid_skips_lookup(self) -> None:
        self.assertIsNone(reverse_dns_lookup("not-an-ip"))


class ApiLookupTests(unittest.TestCase):
    def test_private_ip_is_not_sent_to_api(self) -> None:
        with patch("ip_information.urllib.request.urlopen") as mock_open:
            result = get_ip_information("192.168.1.1")
        mock_open.assert_not_called()
        self.assertEqual(result["type"], "Private")
        self.assertEqual(result["version"], "IPv4")
        self.assertEqual(result["error"], "no_info")

    def test_loopback_is_not_sent_to_api(self) -> None:
        with patch("ip_information.urllib.request.urlopen") as mock_open:
            result = get_ip_information("127.0.0.1")
        mock_open.assert_not_called()
        self.assertEqual(result["type"], "Loopback")

    def test_invalid_ip(self) -> None:
        result = get_ip_information("999.999.999.999")
        self.assertEqual(result["error"], "invalid")
        self.assertIn("Invalid IP", format_ip_information(result))

    @patch("ip_information.reverse_dns_lookup", return_value="dns.google")
    @patch("ip_information.urllib.request.urlopen")
    def test_public_ip_parses_json(
        self,
        mock_open: MagicMock,
        _mock_dns: MagicMock,
    ) -> None:
        payload = {
            "success": True,
            "country": "United States",
            "region": "California",
            "city": "Mountain View",
            "connection": {"asn": 15169, "isp": "Google", "org": "Google LLC"},
            "timezone": {"id": "America/Los_Angeles"},
        }
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(payload).encode("utf-8")
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        mock_open.return_value = response

        result = get_ip_information("8.8.8.8")
        self.assertEqual(result["type"], "Public")
        self.assertEqual(result["country"], "United States")
        self.assertEqual(result["region"], "California")
        self.assertEqual(result["city"], "Mountain View")
        self.assertEqual(result["isp"], "Google")
        self.assertEqual(result["org"], "Google LLC")
        self.assertEqual(result["asn"], "AS15169")
        self.assertEqual(result["timezone"], "America/Los_Angeles")
        self.assertEqual(result["hostname"], "dns.google")
        self.assertIsNone(result["error"])

    @patch("ip_information.reverse_dns_lookup", return_value=None)
    @patch("ip_information.urllib.request.urlopen")
    def test_timeout(self, mock_open: MagicMock, _mock_dns: MagicMock) -> None:
        mock_open.side_effect = TimeoutError()
        result = get_ip_information("8.8.8.8")
        self.assertEqual(result["error"], "timeout")
        self.assertIn("timed out", format_ip_information(result))

    @patch("ip_information.reverse_dns_lookup", return_value=None)
    @patch("ip_information.urllib.request.urlopen")
    def test_unreachable(self, mock_open: MagicMock, _mock_dns: MagicMock) -> None:
        mock_open.side_effect = urllib.error.URLError("offline")
        result = get_ip_information("1.1.1.1")
        self.assertEqual(result["error"], "unreachable")
        self.assertIn("Unable to reach", format_ip_information(result))

    @patch("ip_information.reverse_dns_lookup", return_value=None)
    @patch("ip_information.urllib.request.urlopen")
    def test_rate_limit(self, mock_open: MagicMock, _mock_dns: MagicMock) -> None:
        mock_open.side_effect = urllib.error.HTTPError(
            "https://ipwho.is/8.8.8.8",
            429,
            "Too Many Requests",
            hdrs=None,
            fp=io.BytesIO(b""),
        )
        result = get_ip_information("8.8.8.8")
        self.assertEqual(result["error"], "rate_limit")
        self.assertIn("limit reached", format_ip_information(result))


class ReportTests(unittest.TestCase):
    def test_save_report_writes_file_without_storing_automatically(self) -> None:
        data = {
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
        with tempfile.TemporaryDirectory() as folder:
            path = save_report(data, Path(folder))
            self.assertIsNotNone(path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("CyberToolkit — IP Information Report", text)
            self.assertIn("8.8.8.8", text)
            self.assertIn("IPv4", text)
            self.assertIn("Public", text)

    def test_save_report_rejects_invalid(self) -> None:
        self.assertIsNone(save_report({"ip": "", "error": "invalid"}))


if __name__ == "__main__":
    unittest.main()
