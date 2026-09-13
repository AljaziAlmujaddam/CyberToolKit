#!/usr/bin/env python3
"""CyberToolkit — Log Analyzer (Part 5).

Reads a local log file line by line, classifies common events, extracts
IPv4 addresses, and flags repeated failed logins as potentially
suspicious — not as proof of an attack.

The original log is opened read-only and is never modified or uploaded.
Treat log contents as sensitive.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
SAMPLE_LOG = PROJECT_ROOT / "logs" / "sample.log"
FAILED_LOGIN_THRESHOLD = 3
MAX_SEARCH_DISPLAY = 200

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

FAILED_PATTERNS = (
    "failed login",
    "failed authentication",
    "authentication failed",
    "login failed",
)

SUCCESS_PATTERNS = (
    "successful login",
    "login successful",
    "user logged in",
)

INFO_PATTERN = re.compile(r"\binfo\b", re.IGNORECASE)
WARNING_PATTERN = re.compile(r"\bwarn(?:ing)?\b", re.IGNORECASE)
ERROR_PATTERN = re.compile(r"\berror\b", re.IGNORECASE)


def load_log_file(file_path: str | Path) -> list[str]:
    """Read a log file line by line (read-only). Skip blank lines."""
    path = Path(file_path).expanduser()
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\n\r")
            if line.strip():
                lines.append(line)
    return lines


def classify_event(line: str) -> set[str]:
    """Return event labels found in a single log line."""
    lower = line.lower()
    labels: set[str] = set()

    if INFO_PATTERN.search(line):
        labels.add("info")
    if WARNING_PATTERN.search(line):
        labels.add("warning")
    if ERROR_PATTERN.search(line):
        labels.add("error")
    if any(pattern in lower for pattern in FAILED_PATTERNS):
        labels.add("failed_login")
    if any(pattern in lower for pattern in SUCCESS_PATTERNS):
        labels.add("successful_login")
    return labels


def count_events(log_lines: list[str]) -> dict[str, int]:
    """Count total entries and classified event types."""
    counts = {
        "total": 0,
        "info": 0,
        "warning": 0,
        "error": 0,
        "failed_login": 0,
        "successful_login": 0,
    }
    for line in log_lines:
        counts["total"] += 1
        labels = classify_event(line)
        for key in ("info", "warning", "error", "failed_login", "successful_login"):
            if key in labels:
                counts[key] += 1
    return counts


def search_logs(log_lines: list[str], keyword: str) -> list[str]:
    """Return lines that contain the keyword (case-insensitive)."""
    needle = keyword.strip().lower()
    if not needle:
        raise ValueError("Keyword cannot be empty.")
    return [line for line in log_lines if needle in line.lower()]


def extract_ip_addresses(line: str) -> list[str]:
    """Return unique valid IPv4 addresses found in a line, in order."""
    found: list[str] = []
    seen: set[str] = set()
    for match in IPV4_PATTERN.findall(line):
        try:
            ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            continue
        if match not in seen:
            seen.add(match)
            found.append(match)
    return found


def detect_failed_logins(log_lines: list[str]) -> dict:
    """Count failed-login lines overall and per IP address."""
    per_ip: Counter[str] = Counter()
    total = 0
    for line in log_lines:
        if "failed_login" not in classify_event(line):
            continue
        total += 1
        ips = extract_ip_addresses(line)
        if ips:
            for ip in ips:
                per_ip[ip] += 1
        else:
            per_ip["(no IP in entry)"] += 1
    return {"total": total, "per_ip": dict(per_ip)}


def analyze_ip_activity(log_lines: list[str]) -> dict[str, int]:
    """Count how many log lines mention each IPv4 address."""
    counts: Counter[str] = Counter()
    for line in log_lines:
        for ip in extract_ip_addresses(line):
            counts[ip] += 1
    return dict(counts)


def suspicious_failed_login_ips(
    log_lines: list[str],
    threshold: int = FAILED_LOGIN_THRESHOLD,
) -> dict[str, int]:
    """IPs with failed logins at or above the threshold (potential only)."""
    failed = detect_failed_logins(log_lines)
    return {
        ip: count
        for ip, count in failed["per_ip"].items()
        if ip != "(no IP in entry)" and count >= threshold
    }


def analyze_log_file(file_path: str | Path) -> dict:
    """Run the full local analysis. Does not write a report by itself."""
    lines = load_log_file(file_path)
    failed = detect_failed_logins(lines)
    return {
        "path": str(Path(file_path).expanduser().resolve()),
        "lines": lines,
        "counts": count_events(lines),
        "ip_activity": analyze_ip_activity(lines),
        "failed_logins": failed,
        "suspicious_ips": suspicious_failed_login_ips(lines),
    }


def format_report(data: dict) -> str:
    """Build a text report from analysis results."""
    counts = data["counts"]
    lines = [
        "CyberToolkit — Log Analysis Report",
        "",
        f"File: {data.get('path', '')}",
        "",
        "Statistics",
        "----------",
        f"Total Log Entries: {counts['total']}",
        "",
        f"INFO Events: {counts['info']}",
        f"WARNING Events: {counts['warning']}",
        f"ERROR Events: {counts['error']}",
        "",
        f"Failed Login Attempts: {counts['failed_login']}",
        f"Successful Logins: {counts['successful_login']}",
        "",
        "IP Activity",
        "-----------",
    ]

    activity = data.get("ip_activity") or {}
    if not activity:
        lines.append("No IPv4 addresses found.")
    else:
        for ip, count in sorted(activity.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"{ip} → {count} events")

    lines.extend(["", "Suspicious IPs", "--------------"])
    suspicious = data.get("suspicious_ips") or {}
    if not suspicious:
        lines.append("None (threshold is 3 or more failed logins from one IP).")
        lines.append("This is a basic rule, not proof of an attack.")
    else:
        lines.append("Potentially Suspicious Activity")
        lines.append("This is not confirmation that an attack occurred.")
        lines.append("")
        for ip, count in sorted(suspicious.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"IP Address: {ip}")
            lines.append(f"Failed Attempts: {count}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def generate_report(data: dict, directory: Path | None = None) -> Path:
    """Write the analysis report. Does not copy the original log."""
    folder = directory or REPORTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "Log_Analysis_Report.txt"
    path.write_text(format_report(data), encoding="utf-8")
    return path


def _resolve_log_path(raw_path: str) -> Path | None:
    if not raw_path.strip():
        print("File path cannot be empty.")
        return None

    path = Path(raw_path.strip()).expanduser()
    if not path.exists():
        print("Error: Log file not found.")
        return None
    if path.is_dir():
        print("That path is a directory. Provide a log file path instead.")
        return None
    if not path.is_file():
        print("That path is not a regular file.")
        return None
    return path


def _load_or_error(path: Path) -> list[str] | None:
    try:
        lines = load_log_file(path)
    except PermissionError:
        print("❌ Unable to read file.")
        print("Permission denied.")
        return None
    except OSError as error:
        print(f"Could not read the log file: {error}")
        return None
    return lines


def _print_menu() -> None:
    print()
    print("========================================")
    print("            LOG ANALYZER")
    print("========================================")
    print()
    print("1. Analyze Log File")
    print("2. Search Keyword")
    print("3. Show Suspicious Activity")
    print("4. Save Report")
    print("5. Back")
    print()
    print(f"Sample log: {SAMPLE_LOG}")


def _print_statistics(data: dict) -> None:
    print()
    print(format_report(data), end="")
    if data["counts"]["total"] == 0:
        print()
        print("No log entries found.")


def _run_analyze(last: dict | None) -> dict | None:
    print()
    raw_path = input("Enter log file path: ")
    path = _resolve_log_path(raw_path)
    if path is None:
        return last
    lines = _load_or_error(path)
    if lines is None:
        return last
    data = analyze_log_file(path)
    if data["counts"]["total"] == 0:
        print()
        print("No log entries found.")
        return data
    _print_statistics(data)
    return data


def _run_search(last: dict | None) -> dict | None:
    if last is None:
        print("Analyze a log file first, then search.")
        return last

    print()
    keyword = input("Enter keyword: ")
    if not keyword.strip():
        print("Keyword cannot be empty.")
        return last

    try:
        matches = search_logs(last["lines"], keyword)
    except ValueError as error:
        print(error)
        return last

    print()
    if not matches:
        print("No matching log entries.")
        return last

    shown = matches[:MAX_SEARCH_DISPLAY]
    for index, line in enumerate(shown, start=1):
        print(f"[{index}] {line}")
    if len(matches) > MAX_SEARCH_DISPLAY:
        print()
        print(f"... {len(matches) - MAX_SEARCH_DISPLAY} more matches not shown.")
    return last


def _run_suspicious(last: dict | None) -> dict | None:
    if last is None:
        print("Analyze a log file first.")
        return last

    print()
    print("Potentially Suspicious Activity")
    print("-------------------------------")
    print("Repeated failed logins can be a signal to investigate.")
    print("They do not by themselves prove that an attack occurred.")
    print()

    suspicious = last.get("suspicious_ips") or {}
    if not suspicious:
        print("No IP reached the failed-login threshold")
        print(f"({FAILED_LOGIN_THRESHOLD} or more attempts).")
        return last

    for ip, count in sorted(suspicious.items(), key=lambda item: (-item[1], item[0])):
        print(f"IP Address: {ip}")
        print(f"Failed Attempts: {count}")
        print()
    return last


def _run_save(last: dict | None) -> None:
    if last is None:
        print("Analyze a log file first, then save the report.")
        return
    try:
        path = generate_report(last)
    except OSError as error:
        print(f"Could not write the report: {error}")
        return
    print()
    print(f"Report saved: {path}")
    print("The original log file was not modified.")


def main() -> None:
    print()
    print("Educational note:")
    print("Analyze only logs you are allowed to review.")
    print("Logs can contain usernames and IP addresses.")
    print("This tool only reads files. It never changes them.")

    last: dict | None = None
    while True:
        _print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            last = _run_analyze(last)
        elif choice == "2":
            last = _run_search(last)
        elif choice == "3":
            last = _run_suspicious(last)
        elif choice == "4":
            _run_save(last)
        elif choice == "5":
            print("Leaving Log Analyzer.")
            return
        else:
            print("Invalid choice. Enter 1, 2, 3, 4, or 5.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
