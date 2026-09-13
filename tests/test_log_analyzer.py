#!/usr/bin/env python3
"""Tests for the Log Analyzer module."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_DIR))

from log_analyzer import (  # noqa: E402
    analyze_ip_activity,
    analyze_log_file,
    classify_event,
    count_events,
    detect_failed_logins,
    extract_ip_addresses,
    generate_report,
    load_log_file,
    search_logs,
    suspicious_failed_login_ips,
)

SAMPLE = PROJECT_ROOT / "logs" / "sample.log"


class LogAnalyzerTests(unittest.TestCase):
    def test_normal_log_reads_successfully(self) -> None:
        lines = load_log_file(SAMPLE)
        self.assertGreater(len(lines), 0)
        counts = count_events(lines)
        self.assertEqual(counts["total"], len(lines))
        self.assertGreater(counts["info"], 0)
        self.assertGreater(counts["warning"], 0)
        self.assertGreater(counts["error"], 0)

    def test_empty_log(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            path = Path(handle.name)
        try:
            lines = load_log_file(path)
            self.assertEqual(lines, [])
            self.assertEqual(count_events(lines)["total"], 0)
        finally:
            path.unlink(missing_ok=True)

    def test_missing_file(self) -> None:
        missing = PROJECT_ROOT / "logs" / "does-not-exist.log"
        with self.assertRaises(FileNotFoundError):
            load_log_file(missing)

    def test_failed_logins_mark_suspicious_ip(self) -> None:
        lines = [
            "Failed login from 192.168.1.20",
            "Failed login from 192.168.1.20",
            "Failed login from 192.168.1.20",
        ]
        failed = detect_failed_logins(lines)
        self.assertEqual(failed["total"], 3)
        suspicious = suspicious_failed_login_ips(lines)
        self.assertEqual(suspicious["192.168.1.20"], 3)

    def test_two_failed_logins_are_not_suspicious(self) -> None:
        lines = [
            "Failed login from 10.0.0.1",
            "Failed login from 10.0.0.1",
        ]
        self.assertEqual(suspicious_failed_login_ips(lines), {})

    def test_multiple_ip_activity_is_separate(self) -> None:
        lines = [
            "INFO event from 192.168.1.20",
            "WARNING event from 192.168.1.15",
            "INFO event from 192.168.1.20",
            "ERROR event from 10.0.0.5",
        ]
        activity = analyze_ip_activity(lines)
        self.assertEqual(activity["192.168.1.20"], 2)
        self.assertEqual(activity["192.168.1.15"], 1)
        self.assertEqual(activity["10.0.0.5"], 1)

    def test_search_is_case_insensitive(self) -> None:
        lines = [
            "2026-09-13 10:17:42 WARNING Failed login attempt",
            "INFO heartbeat",
        ]
        for keyword in ("failed", "Failed", "FAILED"):
            matches = search_logs(lines, keyword)
            self.assertEqual(len(matches), 1)
            self.assertIn("Failed login", matches[0])

    def test_empty_keyword_rejected(self) -> None:
        with self.assertRaises(ValueError):
            search_logs(["INFO ok"], "  ")

    def test_extract_ipv4(self) -> None:
        line = "2026-09-13 10:17:42 Failed login from 192.168.1.20"
        self.assertEqual(extract_ip_addresses(line), ["192.168.1.20"])

    def test_classify_warning_and_failed_login(self) -> None:
        labels = classify_event("WARNING Failed login attempt")
        self.assertIn("warning", labels)
        self.assertIn("failed_login", labels)

    def test_successful_login_patterns(self) -> None:
        self.assertIn("successful_login", classify_event("User logged in from 10.0.0.5"))
        self.assertIn("successful_login", classify_event("Login successful for bob"))

    def test_generate_report_does_not_copy_log_body(self) -> None:
        data = analyze_log_file(SAMPLE)
        with tempfile.TemporaryDirectory() as folder:
            path = generate_report(data, Path(folder))
            text = path.read_text(encoding="utf-8")
        self.assertIn("Log Analysis Report", text)
        self.assertIn("192.168.1.20", text)
        self.assertIn("Potentially Suspicious Activity", text)
        self.assertNotIn("password=secret", text)

    def test_sample_log_flags_192_168_1_20(self) -> None:
        data = analyze_log_file(SAMPLE)
        self.assertGreaterEqual(data["suspicious_ips"].get("192.168.1.20", 0), 3)


if __name__ == "__main__":
    unittest.main()
