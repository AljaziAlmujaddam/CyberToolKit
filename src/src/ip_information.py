#!/usr/bin/env python3
"""CyberToolkit — IP Information Tool (Part 4).

Validates an IP address locally, classifies it, optionally queries a
public IP information API, and can attempt reverse DNS.

This is an educational, defensive lookup tool. It does not scan ports,
exploit hosts, or store lookups unless the user saves a report.

Looking up a public IP sends that address to the API provider.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "data"
REQUEST_TIMEOUT = 8
USER_AGENT = "CyberToolkit-IP-Information/1.0 (educational)"

# ipwho.is does not require a key for the public endpoint.
# If a key is ever needed, set IPWHO_API_KEY in the environment — never in source.
API_BASE = "https://ipwho.is/"


def validate_ip(ip_address: str) -> bool:
    """Return True if the text is a valid IPv4 or IPv6 address."""
    text = ip_address.strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def get_ip_version(ip_address: str) -> str | None:
    """Return 'IPv4' or 'IPv6', or None if the address is invalid."""
    try:
        addr = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return None
    return f"IPv{addr.version}"


def identify_ip_type(ip_address: str) -> str:
    """Classify an address as Public, Private, Loopback, Reserved, or Invalid."""
    try:
        addr = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return "Invalid"

    if addr.is_loopback:
        return "Loopback"
    if (
        addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
    ):
        return "Reserved"
    if addr.is_private:
        return "Private"
    return "Public"


def reverse_dns_lookup(ip_address: str) -> str | None:
    """Return a reverse-DNS hostname, or None if none is available."""
    if not validate_ip(ip_address):
        return None
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip_address.strip())
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    hostname = (hostname or "").strip()
    return hostname or None


def _empty_info(ip_address: str) -> dict:
    version = get_ip_version(ip_address)
    ip_type = identify_ip_type(ip_address)
    return {
        "ip": ip_address.strip(),
        "version": version,
        "type": ip_type,
        "hostname": None,
        "country": None,
        "region": None,
        "city": None,
        "isp": None,
        "org": None,
        "asn": None,
        "timezone": None,
        "error": None,
    }


def _parse_api_payload(payload: dict, info: dict) -> dict:
    if not payload.get("success", True):
        info["error"] = "no_info"
        return info

    info["country"] = payload.get("country") or None
    info["region"] = payload.get("region") or None
    info["city"] = payload.get("city") or None

    connection = payload.get("connection")
    if isinstance(connection, dict):
        asn = connection.get("asn")
        info["isp"] = connection.get("isp") or None
        info["org"] = connection.get("org") or None
        if asn not in (None, "", 0):
            info["asn"] = f"AS{asn}" if not str(asn).upper().startswith("AS") else str(asn)

    timezone = payload.get("timezone")
    if isinstance(timezone, dict):
        info["timezone"] = timezone.get("id") or None
    elif isinstance(timezone, str) and timezone:
        info["timezone"] = timezone

    return info


def get_ip_information(ip_address: str) -> dict:
    """Validate, classify, reverse-DNS, and (for public IPs) query the API."""
    text = ip_address.strip()
    info = _empty_info(text)

    if info["type"] == "Invalid" or info["version"] is None:
        info["error"] = "invalid"
        return info

    info["hostname"] = reverse_dns_lookup(text)

    if info["type"] != "Public":
        info["error"] = "no_info"
        return info

    info.update(_fetch_public_ip_details(text, info))
    return info


def _fetch_public_ip_details(ip_address: str, info: dict) -> dict:
    encoded = urllib.parse.quote(ip_address, safe="")
    url = f"{API_BASE}{encoded}"
    token = os.environ.get("IPWHO_API_KEY", "").strip()
    if token:
        url = f"{url}?{urllib.parse.urlencode({'key': token})}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            status = getattr(response, "status", 200)
            body = response.read().decode("utf-8")
    except TimeoutError:
        info["error"] = "timeout"
        return info
    except urllib.error.HTTPError as error:
        if error.code == 429:
            info["error"] = "rate_limit"
        else:
            info["error"] = "unreachable"
        return info
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, TimeoutError) or (
            isinstance(reason, OSError) and "timed out" in str(reason).lower()
        ):
            info["error"] = "timeout"
        else:
            info["error"] = "unreachable"
        return info
    except OSError:
        info["error"] = "unreachable"
        return info

    if status == 429:
        info["error"] = "rate_limit"
        return info

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        info["error"] = "unreachable"
        return info

    if not isinstance(payload, dict):
        info["error"] = "no_info"
        return info

    return _parse_api_payload(payload, info)


def _value(text: str | None) -> str:
    if text is None or str(text).strip() == "":
        return "Not available"
    return str(text)


def format_ip_information(data: dict) -> str:
    """Return a terminal-friendly report. Does not print."""
    if data.get("error") == "invalid":
        return "❌ Invalid IP address."

    lines = [
        "IP Information",
        "-------------------------",
        "",
        f"IP Address : {data.get('ip', '')}",
        f"Version    : {_value(data.get('version'))}",
        f"Type       : {_value(data.get('type'))}",
        "",
        f"Hostname   : {_value(data.get('hostname'))}",
        f"Country    : {_value(data.get('country'))}",
        f"Region     : {_value(data.get('region'))}",
        f"City       : {_value(data.get('city'))}",
        "",
        f"ISP        : {_value(data.get('isp'))}",
        f"Organization: {_value(data.get('org'))}",
        f"ASN        : {_value(data.get('asn'))}",
        f"Timezone   : {_value(data.get('timezone'))}",
    ]

    error = data.get("error")
    if error == "timeout":
        lines.extend(["", "❌ Request timed out."])
    elif error == "unreachable":
        lines.extend(
            [
                "",
                "❌ Unable to reach the IP information service.",
                "Please try again later.",
            ]
        )
    elif error == "rate_limit":
        lines.extend(["", "⚠️ API request limit reached."])
    elif error == "no_info" and data.get("type") == "Public":
        lines.extend(["", "ℹ️ No additional information is available for this IP."])
    elif error == "no_info":
        lines.extend(
            [
                "",
                "ℹ️ No additional information is available for this IP.",
                "Private, loopback, and reserved addresses are not sent to the API.",
            ]
        )

    return "\n".join(lines)


def display_ip_information(data: dict) -> None:
    print()
    print(format_ip_information(data))


def save_report(data: dict, directory: Path | None = None) -> Path | None:
    """Write a report only when called. Returns the file path, or None."""
    if data.get("error") == "invalid" or not data.get("ip"):
        return None

    folder = directory or REPORTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    safe_ip = data["ip"].replace(":", "_").replace("/", "_")
    path = folder / f"IP_Report_{safe_ip}.txt"
    header = "CyberToolkit — IP Information Report\n\n"
    path.write_text(header + format_ip_information(data) + "\n", encoding="utf-8")
    return path


def _print_menu() -> None:
    print()
    print("========================================")
    print("        IP INFORMATION TOOL")
    print("========================================")
    print()
    print("1. Analyze IP Address")
    print("2. Reverse DNS Lookup")
    print("3. Save Report")
    print("4. Back")
    print()


def _prompt_ip() -> str | None:
    print()
    text = input("Enter an IP address: ").strip()
    if not text:
        print("❌ Invalid IP address.")
        return None
    if not validate_ip(text):
        print("❌ Invalid IP address.")
        return None
    return text


def _run_analyze(last_result: dict | None) -> dict | None:
    ip_address = _prompt_ip()
    if ip_address is None:
        return last_result
    print()
    print("Privacy note: a public IP is sent to the IP information API.")
    result = get_ip_information(ip_address)
    display_ip_information(result)
    return result


def _run_reverse_dns(last_result: dict | None) -> dict | None:
    ip_address = _prompt_ip()
    if ip_address is None:
        return last_result

    hostname = reverse_dns_lookup(ip_address)
    print()
    print("Reverse DNS Lookup")
    print("------------------")
    print(f"IP Address: {ip_address}")
    print("Hostname:")
    print(hostname if hostname else "Not available")

    result = last_result or _empty_info(ip_address)
    if result.get("ip") == ip_address:
        result = dict(result)
        result["hostname"] = hostname
        return result
    info = _empty_info(ip_address)
    info["hostname"] = hostname
    return info


def _run_save_report(last_result: dict | None) -> None:
    if last_result is None:
        print("Analyze an IP address first, then save the report.")
        return
    path = save_report(last_result)
    if path is None:
        print("There is no valid report to save.")
        return
    print()
    print(f"Report saved: {path}")


def main() -> None:
    print()
    print("Educational note:")
    print("This tool looks up IP information for learning.")
    print("It does not scan, attack, or log addresses automatically.")
    print("Public lookups are sent to ipwho.is over HTTPS.")

    last_result: dict | None = None
    while True:
        _print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            last_result = _run_analyze(last_result)
        elif choice == "2":
            last_result = _run_reverse_dns(last_result)
        elif choice == "3":
            _run_save_report(last_result)
        elif choice == "4":
            print("Leaving IP Information Tool.")
            return
        else:
            print("Invalid choice. Enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
