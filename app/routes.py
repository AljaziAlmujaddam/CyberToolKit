"""HTTP routes for CyberToolkit Version 2.

Serves the dashboard and JSON APIs that call Version 1 modules.
Routes must not run shell commands or execute browser-supplied code.
"""

from __future__ import annotations

from pathlib import Path
import tempfile

from flask import Blueprint, current_app, jsonify, render_template, request

from app.modules.hash_tool import DISPLAY_NAMES, hash_text
from app.modules.integrity_checker import add_file, check_file, list_monitored_files
from app.modules.ip_information import get_ip_information
from app.modules.log_analyzer import (
    FAILED_LOGIN_THRESHOLD,
    analyze_log_file,
    load_log_file,
    search_logs,
)
from app.modules.password_analyzer import analyze_password
from app.safe_files import resolve_in_directory, safe_filename

bp = Blueprint("main", __name__)

MAX_PASSWORD_LENGTH = 1024
MAX_HASH_TEXT_LENGTH = 32 * 1024
MD5_EDUCATIONAL_WARNING = (
    "MD5 is provided for educational comparison and should not be used "
    "for modern security purposes."
)

ALGORITHM_ALIASES = {
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha512": "sha512",
    "sha-512": "sha512",
    "md5": "md5",
}

INTEGRITY_LABELS = {
    "unchanged": "Integrity Verified",
    "modified": "File Modified",
    "missing": "File Missing",
    "not_registered": "File Not Registered",
    "unreadable": "Unable to read file",
    "added": "File registered",
    "updated": "Reference hash updated",
    "invalid": "Invalid file",
}

IP_ERROR_MESSAGES = {
    "invalid": "Invalid IP address.",
    "timeout": "The IP information service timed out. Please try again later.",
    "unreachable": "Unable to reach the IP information service. Please try again later.",
    "rate_limit": "API request limit reached. Please try again later.",
    "no_info": "No additional information is available for this IP.",
}


def _api_error(message: str, status: int):
    return jsonify({"error": message}), status


def _json_object():
    payload = request.get_json(silent=True)
    if payload is None:
        return None, _api_error("Request body must be valid JSON.", 400)
    if not isinstance(payload, dict):
        return None, _api_error("Request body must be a JSON object.", 400)
    return payload, None


def _monitored_dir() -> Path:
    return Path(current_app.config["MONITORED_DIR"])


def _integrity_db() -> Path:
    return Path(current_app.config["INTEGRITY_DB"])


def _inside_monitored(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(_monitored_dir().resolve())
    except OSError:
        return False


def _public_integrity(result: dict) -> dict:
    """Return status fields without exposing absolute server paths."""
    name = result.get("name") or Path(str(result.get("path", ""))).name
    public = {
        "status": result.get("status"),
        "label": INTEGRITY_LABELS.get(result.get("status", ""), result.get("status")),
        "name": name,
    }
    for key in ("sha256", "original_hash", "current_hash", "detail"):
        if key in result:
            public[key] = result[key]
    return public


def _save_upload(uploaded) -> tuple[Path | None, tuple | None]:
    filename = safe_filename(uploaded.filename)
    if filename is None:
        return None, _api_error("Invalid file name.", 400)
    destination = resolve_in_directory(_monitored_dir(), filename)
    if destination is None:
        return None, _api_error("Invalid file path.", 400)
    destination.parent.mkdir(parents=True, exist_ok=True)
    uploaded.save(destination)
    return destination, None


@bp.get("/")
def index():
    """Dashboard with navigation, hero, tool cards, and about."""
    return render_template("index.html")


@bp.get("/api/status")
def api_status():
    """Prove that the browser can reach Flask and receive JSON."""
    return (
        jsonify(
            {
                "status": "online",
                "application": "CyberToolkit",
            }
        ),
        200,
    )


@bp.post("/api/password/analyze")
def api_password_analyze():
    """Validate JSON, then reuse the Version 1 Password Analyzer."""
    payload, error = _json_object()
    if error is not None:
        return error

    if "password" not in payload:
        return _api_error("Password is required.", 400)

    password = payload["password"]
    if not isinstance(password, str):
        return _api_error("Field 'password' must be a string.", 400)
    if password.strip() == "":
        return _api_error("Password is required.", 400)
    if len(password) > MAX_PASSWORD_LENGTH:
        return _api_error("Password is too long.", 400)

    result = analyze_password(password)
    return jsonify(result), 200


@bp.post("/api/hash/calculate")
def api_hash_calculate():
    """Validate JSON and an allowlisted algorithm, then hash text in Python."""
    payload, error = _json_object()
    if error is not None:
        return error

    if "text" not in payload:
        return _api_error("Text is required.", 400)
    if "algorithm" not in payload:
        return _api_error("Algorithm is required.", 400)

    text = payload["text"]
    algorithm_raw = payload["algorithm"]
    if not isinstance(text, str):
        return _api_error("Field 'text' must be a string.", 400)
    if not isinstance(algorithm_raw, str):
        return _api_error("Field 'algorithm' must be a string.", 400)
    if text == "":
        return _api_error("Text is required.", 400)
    if len(text) > MAX_HASH_TEXT_LENGTH:
        return _api_error("Text is too long.", 400)

    algorithm = ALGORITHM_ALIASES.get(algorithm_raw.strip().lower())
    if algorithm is None:
        return _api_error(
            "Unsupported algorithm. Use sha256, sha512, or md5.",
            400,
        )

    digest = hash_text(text, algorithm)
    response = {
        "algorithm": DISPLAY_NAMES[algorithm],
        "hash": digest,
    }
    if algorithm == "md5":
        response["warning"] = MD5_EDUCATIONAL_WARNING
    return jsonify(response), 200


@bp.post("/api/integrity/register")
def api_integrity_register():
    """Save an uploaded file inside data/monitored/ and store its SHA-256."""
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return _api_error("No file selected.", 400)

    destination, error = _save_upload(uploaded)
    if error is not None:
        return error

    result = add_file(destination, _integrity_db())
    if result["status"] in {"invalid", "unreadable"}:
        return _api_error(result.get("detail") or "Unable to register file.", 400)
    return jsonify(_public_integrity(result)), 200


@bp.post("/api/integrity/check")
def api_integrity_check():
    """Compare a file in the allowed directory with its stored SHA-256."""
    uploaded = request.files.get("file")
    if uploaded is not None and uploaded.filename:
        destination, error = _save_upload(uploaded)
        if error is not None:
            return error
        result = check_file(destination, _integrity_db())
        return jsonify(_public_integrity(result)), 200

    payload, error = _json_object()
    if error is not None:
        return error
    filename = payload.get("filename")
    if not isinstance(filename, str) or filename.strip() == "":
        return _api_error("File name is required.", 400)

    destination = resolve_in_directory(_monitored_dir(), filename)
    if destination is None:
        return _api_error("Invalid file path.", 400)
    result = check_file(destination, _integrity_db())
    return jsonify(_public_integrity(result)), 200


@bp.get("/api/integrity/files")
def api_integrity_files():
    """List registered files that live inside the allowed directory."""
    records = []
    for item in list_monitored_files(_integrity_db()):
        stored = Path(item["path"])
        try:
            resolved = stored.resolve()
        except OSError:
            continue
        if not _inside_monitored(resolved):
            continue
        records.append({"name": stored.name, "sha256": item["sha256"]})
    return jsonify({"files": records}), 200


@bp.post("/api/integrity/check-all")
def api_integrity_check_all():
    """Check every registered file that is inside the allowed directory."""
    results = []
    for item in list_monitored_files(_integrity_db()):
        stored = Path(item["path"])
        try:
            resolved = stored.resolve()
        except OSError:
            continue
        if not _inside_monitored(resolved):
            continue
        results.append(_public_integrity(check_file(resolved, _integrity_db())))
    return jsonify({"files": results}), 200


@bp.post("/api/ip/analyze")
def api_ip_analyze():
    """Validate and classify an IP; look up public addresses via the V1 module."""
    payload, error = _json_object()
    if error is not None:
        return error

    if "ip" not in payload:
        return _api_error("IP address is required.", 400)
    ip_address = payload["ip"]
    if not isinstance(ip_address, str):
        return _api_error("Field 'ip' must be a string.", 400)
    if ip_address.strip() == "":
        return _api_error("IP address is required.", 400)

    result = get_ip_information(ip_address)
    public = {
        "ip": result.get("ip"),
        "version": result.get("version"),
        "type": result.get("type"),
        "hostname": result.get("hostname"),
        "country": result.get("country"),
        "region": result.get("region"),
        "city": result.get("city"),
        "isp": result.get("isp"),
        "org": result.get("org"),
        "asn": result.get("asn"),
        "timezone": result.get("timezone"),
    }

    error_code = result.get("error")
    if error_code == "invalid":
        return _api_error(IP_ERROR_MESSAGES["invalid"], 400)

    if public["type"] == "Public":
        public["privacy_note"] = (
            "This public IP was sent to the IP information provider (ipwho.is)."
        )
    else:
        public["note"] = (
            "Private, loopback, and reserved addresses are not sent to the "
            "external API."
        )

    if error_code in {"timeout", "unreachable", "rate_limit"}:
        status = {"timeout": 504, "unreachable": 502, "rate_limit": 429}[error_code]
        public["error"] = IP_ERROR_MESSAGES[error_code]
        return jsonify(public), status

    if error_code == "no_info" and public["type"] == "Public":
        public["error"] = IP_ERROR_MESSAGES["no_info"]

    return jsonify(public), 200


MAX_SEARCH_MATCHES = 50
LOG_NOTE = (
    "Repeated failed logins are potentially suspicious, not proof of an attack. "
    "Logs are analyzed locally and are not sent to an external service."
)


def _logs_dir() -> Path:
    return Path(current_app.config["LOGS_DIR"])


def _max_log_bytes() -> int:
    return int(current_app.config.get("MAX_LOG_BYTES", 512 * 1024))


def _public_log(data: dict, name: str) -> dict:
    counts = data.get("counts") or {}
    suspicious = data.get("suspicious_ips") or {}
    return {
        "name": name,
        "total_entries": counts.get("total", 0),
        "info": counts.get("info", 0),
        "warnings": counts.get("warning", 0),
        "errors": counts.get("error", 0),
        "failed_logins": counts.get("failed_login", 0),
        "successful_logins": counts.get("successful_login", 0),
        "ip_addresses": data.get("ip_activity") or {},
        "suspicious_activity": [
            {"ip": ip, "failed_attempts": count}
            for ip, count in sorted(
                suspicious.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "threshold": FAILED_LOGIN_THRESHOLD,
        "note": LOG_NOTE,
    }


def _reject_binary(raw: bytes) -> bool:
    return b"\x00" in raw[:8192]


def _save_temp_upload(uploaded):
    filename = safe_filename(uploaded.filename)
    if filename is None:
        return None, None, _api_error("Invalid file name.", 400)

    uploaded.stream.seek(0, 2)
    size = uploaded.stream.tell()
    uploaded.stream.seek(0)
    if size > _max_log_bytes():
        return None, None, _api_error(
            "Unable to analyze the selected log file. Please verify that the "
            "file is valid and within the allowed size limit.",
            413,
        )

    peek = uploaded.stream.read(8192)
    uploaded.stream.seek(0)
    if _reject_binary(peek):
        return None, None, _api_error(
            "Unable to analyze the selected log file. Please verify that the "
            "file is valid and within the allowed size limit.",
            400,
        )

    handle = tempfile.NamedTemporaryFile(
        prefix="cybertoolkit-log-",
        suffix=".log",
        delete=False,
    )
    try:
        uploaded.save(handle.name)
    finally:
        handle.close()
    return Path(handle.name), filename, None


def _resolve_log_filename(filename: str) -> tuple[Path | None, tuple | None]:
    destination = resolve_in_directory(_logs_dir(), filename)
    if destination is None:
        return None, _api_error("Invalid file path.", 400)
    if not destination.is_file():
        return None, _api_error("Log file not found.", 400)
    if destination.stat().st_size > _max_log_bytes():
        return None, _api_error(
            "Unable to analyze the selected log file. Please verify that the "
            "file is valid and within the allowed size limit.",
            413,
        )
    return destination, None


def _log_from_request():
    """Return (path, display_name, cleanup, error_response)."""
    uploaded = request.files.get("file")
    if uploaded is not None and uploaded.filename:
        path, name, error = _save_temp_upload(uploaded)
        if error is not None:
            return None, None, None, error
        return path, name, path, None

    filename = None
    if request.is_json:
        payload, error = _json_object()
        if error is not None:
            return None, None, None, error
        raw = payload.get("filename")
        if isinstance(raw, str):
            filename = raw
    else:
        raw = request.form.get("filename")
        if isinstance(raw, str):
            filename = raw

    if not filename or not filename.strip():
        return None, None, None, _api_error("No file selected.", 400)

    path, error = _resolve_log_filename(filename)
    if error is not None:
        return None, None, None, error
    return path, path.name, None, None


@bp.get("/api/log/files")
def api_log_files():
    """List log files in the allowed logs/ directory."""
    folder = _logs_dir()
    names = []
    if folder.is_dir():
        for item in sorted(folder.iterdir()):
            if not item.is_file():
                continue
            if item.name.startswith("."):
                continue
            if safe_filename(item.name) != item.name:
                continue
            names.append(item.name)
    return jsonify({"files": names}), 200


@bp.post("/api/log/analyze")
def api_log_analyze():
    """Analyze an uploaded log or a file from logs/ using Version 1 logic."""
    path, name, cleanup, error = _log_from_request()
    if error is not None:
        return error
    try:
        data = analyze_log_file(path)
    except PermissionError:
        return _api_error(
            "Unable to analyze the selected log file. Please verify that the "
            "file is valid and within the allowed size limit.",
            400,
        )
    except OSError:
        return _api_error(
            "Unable to analyze the selected log file. Please verify that the "
            "file is valid and within the allowed size limit.",
            400,
        )
    finally:
        if cleanup is not None:
            Path(cleanup).unlink(missing_ok=True)
    return jsonify(_public_log(data, name)), 200


@bp.post("/api/log/search")
def api_log_search():
    """Search an authorized log. Keyword matching stays in the V1 module."""
    keyword = None
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            keyword = payload.get("keyword")
    else:
        keyword = request.form.get("keyword")

    if not isinstance(keyword, str) or keyword.strip() == "":
        return _api_error("Keyword is required.", 400)

    path, _name, cleanup, error = _log_from_request()
    if error is not None:
        return error
    try:
        lines = load_log_file(path)
        matches = search_logs(lines, keyword)
    except ValueError:
        return _api_error("Keyword is required.", 400)
    except OSError:
        return _api_error(
            "Unable to analyze the selected log file. Please verify that the "
            "file is valid and within the allowed size limit.",
            400,
        )
    finally:
        if cleanup is not None:
            Path(cleanup).unlink(missing_ok=True)

    shown = matches[:MAX_SEARCH_MATCHES]
    return (
        jsonify(
            {
                "keyword": keyword.strip(),
                "match_count": len(matches),
                "matches": shown,
                "truncated": len(matches) > MAX_SEARCH_MATCHES,
            }
        ),
        200,
    )
