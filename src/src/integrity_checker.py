#!/usr/bin/env python3
"""CyberToolkit — File Integrity Checker (Part 3).

Registers local files by SHA-256 and later compares the current digest
with the stored reference. Monitored files are read-only. Only path and
hash are stored — never file contents.

This is an educational integrity monitor, not an enterprise control.
If both a monitored file and monitored_files.json are changed, the
check can be fooled.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from hash_calculator import compare_hashes, hash_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = PROJECT_ROOT / "data" / "monitored_files.json"

STATUS_UNCHANGED = "unchanged"
STATUS_MODIFIED = "modified"
STATUS_MISSING = "missing"
STATUS_NOT_REGISTERED = "not_registered"
STATUS_UNREADABLE = "unreadable"
STATUS_ADDED = "added"
STATUS_UPDATED = "updated"
STATUS_REMOVED = "removed"
STATUS_INVALID = "invalid"

STATUS_LABELS = {
    STATUS_UNCHANGED: "✓ File unchanged",
    STATUS_MODIFIED: "⚠️ File modified",
    STATUS_MISSING: "❌ File not found",
    STATUS_NOT_REGISTERED: "ℹ️ File is not registered",
    STATUS_UNREADABLE: "❌ Unable to read file.",
    STATUS_ADDED: "✓ File added for monitoring",
    STATUS_UPDATED: "✓ Reference hash updated",
    STATUS_REMOVED: "✓ File removed from monitoring",
}


def calculate_file_hash(file_path: str | Path) -> str:
    """Return the SHA-256 hex digest of a file (read-only, chunked)."""
    return hash_file(file_path, "sha256")


def load_monitored_files(database_path: Path | None = None) -> list[dict]:
    """Load monitored file records. Missing or empty files yield []."""
    path = database_path or DATABASE_PATH
    if not path.exists():
        return []

    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return []

    if not raw:
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []

    files = payload.get("files", []) if isinstance(payload, dict) else []
    if not isinstance(files, list):
        return []

    records = []
    for item in files:
        if not isinstance(item, dict):
            continue
        stored_path = item.get("path")
        stored_hash = item.get("sha256")
        if isinstance(stored_path, str) and isinstance(stored_hash, str):
            records.append({"path": stored_path, "sha256": stored_hash})
    return records


def save_monitored_files(
    data: list[dict],
    database_path: Path | None = None,
) -> None:
    """Write path + SHA-256 records only. Never writes file contents."""
    path = database_path or DATABASE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "files": [
            {"path": item["path"], "sha256": item["sha256"]}
            for item in data
        ]
    }
    path.write_text(
        json.dumps(payload, indent=4) + "\n",
        encoding="utf-8",
    )


def _resolve_existing_file(raw_path: str) -> Path | None:
    if not raw_path.strip():
        print("File path cannot be empty.")
        return None

    path = Path(raw_path.strip()).expanduser()

    if not path.exists():
        print(f"No file found at: {path}")
        return None
    if path.is_dir():
        print("That path is a directory. Provide a file path instead.")
        return None
    if not path.is_file():
        print("That path is not a regular file.")
        return None
    return path.resolve()


def _lookup(records: list[dict], resolved: Path) -> dict | None:
    key = str(resolved)
    for item in records:
        if item["path"] == key:
            return item
    return None


def add_file(
    file_path: str | Path,
    database_path: Path | None = None,
) -> dict:
    """Register a file: store its path and current SHA-256 hash."""
    path = Path(file_path).expanduser()
    if not str(file_path).strip():
        return {"status": STATUS_INVALID, "detail": "File path cannot be empty."}
    if not path.exists():
        return {"status": STATUS_MISSING, "detail": f"No file found at: {path}"}
    if path.is_dir():
        return {
            "status": STATUS_INVALID,
            "detail": "That path is a directory. Provide a file path instead.",
        }
    if not path.is_file():
        return {
            "status": STATUS_INVALID,
            "detail": "That path is not a regular file.",
        }

    resolved = path.resolve()

    try:
        digest = calculate_file_hash(resolved)
    except PermissionError:
        return {
            "status": STATUS_UNREADABLE,
            "path": str(resolved),
            "name": resolved.name,
            "detail": "Permission denied.",
        }
    except OSError as error:
        return {
            "status": STATUS_UNREADABLE,
            "path": str(resolved),
            "name": resolved.name,
            "detail": str(error),
        }

    records = load_monitored_files(database_path)
    existing = _lookup(records, resolved)
    if existing is None:
        records.append({"path": str(resolved), "sha256": digest})
        status = STATUS_ADDED
    else:
        existing["sha256"] = digest
        status = STATUS_UPDATED

    save_monitored_files(records, database_path)
    return {
        "status": status,
        "path": str(resolved),
        "name": resolved.name,
        "sha256": digest,
    }


def check_file(
    file_path: str | Path,
    database_path: Path | None = None,
) -> dict:
    """Compare the current SHA-256 of a file with its stored reference."""
    if not str(file_path).strip():
        return {"status": STATUS_INVALID, "detail": "File path cannot be empty."}

    path = Path(file_path).expanduser()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    records = load_monitored_files(database_path)
    record = _lookup(records, resolved)

    if record is None:
        if path.exists() and path.is_file():
            return {
                "status": STATUS_NOT_REGISTERED,
                "path": str(resolved),
                "name": resolved.name,
            }
        if path.exists() and path.is_dir():
            return {
                "status": STATUS_INVALID,
                "detail": "That path is a directory. Provide a file path instead.",
            }
        return {
            "status": STATUS_MISSING,
            "path": str(path),
            "name": path.name,
            "detail": "File is not registered",
        }

    original = record["sha256"]
    stored = Path(record["path"])

    if not stored.exists() or not stored.is_file():
        return {
            "status": STATUS_MISSING,
            "path": record["path"],
            "name": stored.name,
            "original_hash": original,
            "current_hash": None,
        }

    try:
        current = calculate_file_hash(stored)
    except PermissionError:
        return {
            "status": STATUS_UNREADABLE,
            "path": record["path"],
            "name": stored.name,
            "original_hash": original,
            "detail": "Permission denied.",
        }
    except OSError as error:
        return {
            "status": STATUS_UNREADABLE,
            "path": record["path"],
            "name": stored.name,
            "original_hash": original,
            "detail": str(error),
        }

    unchanged = compare_hashes(original, current)
    return {
        "status": STATUS_UNCHANGED if unchanged else STATUS_MODIFIED,
        "path": record["path"],
        "name": stored.name,
        "original_hash": original,
        "current_hash": current,
    }


def check_all_files(database_path: Path | None = None) -> list[dict]:
    """Check every registered file against its stored SHA-256."""
    records = load_monitored_files(database_path)
    return [check_file(item["path"], database_path) for item in records]


def list_monitored_files(database_path: Path | None = None) -> list[dict]:
    """Return the registered path/hash records."""
    return load_monitored_files(database_path)


def remove_file(
    file_path: str | Path,
    database_path: Path | None = None,
) -> dict:
    """Stop monitoring a file. Does not delete the file itself."""
    if not str(file_path).strip():
        return {"status": STATUS_INVALID, "detail": "File path cannot be empty."}

    path = Path(file_path).expanduser()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    records = load_monitored_files(database_path)
    remaining = [item for item in records if item["path"] != str(resolved)]

    if len(remaining) == len(records):
        return {
            "status": STATUS_NOT_REGISTERED,
            "path": str(resolved),
            "name": resolved.name,
        }

    save_monitored_files(remaining, database_path)
    return {
        "status": STATUS_REMOVED,
        "path": str(resolved),
        "name": resolved.name,
    }


def _print_menu() -> None:
    print()
    print("========================================")
    print("       FILE INTEGRITY CHECKER")
    print("========================================")
    print()
    print("1. Add File")
    print("2. Check File")
    print("3. Check All Files")
    print("4. List Monitored Files")
    print("5. Remove File")
    print("6. Back")
    print()


def _print_add_result(result: dict) -> None:
    status = result["status"]
    if status in {STATUS_INVALID, STATUS_MISSING, STATUS_UNREADABLE}:
        if status == STATUS_UNREADABLE:
            print(STATUS_LABELS[STATUS_UNREADABLE])
            if result.get("detail"):
                print(result["detail"])
        else:
            print(result.get("detail", STATUS_LABELS.get(status, status)))
        return

    print()
    print("File:")
    print(result["name"])
    print()
    print("SHA-256:")
    print(result["sha256"])
    print()
    print("Status:")
    print(STATUS_LABELS[status])


def _print_check_result(result: dict, detailed: bool = True) -> None:
    status = result["status"]
    if status == STATUS_INVALID:
        print(result.get("detail", "Invalid path."))
        return

    if not detailed:
        label = {
            STATUS_UNCHANGED: "✓ Unchanged",
            STATUS_MODIFIED: "⚠️ Modified",
            STATUS_MISSING: "❌ Missing",
            STATUS_NOT_REGISTERED: "ℹ️ Not registered",
            STATUS_UNREADABLE: "❌ Unreadable",
        }.get(status, status)
        name = result.get("name") or Path(result.get("path", "")).name
        print(f"{name:<24} {label}")
        return

    print()
    print("File Integrity Check")
    print("--------------------")
    print(f"File: {result.get('name', '')}")
    print()

    if result.get("original_hash"):
        print("Original Hash:")
        print(result["original_hash"])
        print()

    if result.get("current_hash"):
        print("Current Hash:")
        print(result["current_hash"])
        print()

    if status == STATUS_UNCHANGED:
        print("✓ Integrity verified")
        print("The file has not changed.")
    elif status == STATUS_MODIFIED:
        print("⚠️ WARNING")
        print("The file has been modified.")
    elif status == STATUS_MISSING:
        print(STATUS_LABELS[STATUS_MISSING])
        if result.get("detail"):
            print(result["detail"])
        else:
            print("The file was registered but is no longer at the stored path.")
    elif status == STATUS_NOT_REGISTERED:
        print(STATUS_LABELS[STATUS_NOT_REGISTERED])
    elif status == STATUS_UNREADABLE:
        print(STATUS_LABELS[STATUS_UNREADABLE])
        if result.get("detail"):
            print(result["detail"])


def _run_add_file() -> None:
    print()
    raw_path = input("Enter file path: ")
    path = _resolve_existing_file(raw_path)
    if path is None:
        return
    result = add_file(path)
    _print_add_result(result)


def _run_check_file() -> None:
    print()
    raw_path = input("Enter file path: ")
    if not raw_path.strip():
        print("File path cannot be empty.")
        return
    result = check_file(raw_path)
    _print_check_result(result)


def _run_check_all() -> None:
    results = check_all_files()
    print()
    print("Integrity Scan")
    print("---------------")
    print()
    if not results:
        print("No files are being monitored.")
        print()
        print("Scan complete.")
        return

    print("Running Integrity Scan...")
    print()
    for result in results:
        _print_check_result(result, detailed=False)
    print()
    print("Scan complete.")


def _run_list_files() -> None:
    records = list_monitored_files()
    print()
    print("Monitored Files")
    print("----------------")
    print()
    if not records:
        print("No files are being monitored.")
        return
    for index, item in enumerate(records, start=1):
        name = Path(item["path"]).name
        print(f"{index}. {name}")
        print(f"   {item['path']}")


def _run_remove_file() -> None:
    print()
    raw_path = input("Enter file path: ")
    if not raw_path.strip():
        print("File path cannot be empty.")
        return
    result = remove_file(raw_path)
    print()
    print(STATUS_LABELS.get(result["status"], result.get("detail", result["status"])))


def main() -> None:
    print()
    print("Educational note:")
    print("This tool stores reference hashes locally in JSON.")
    print("If someone can change both a file and its stored hash,")
    print("the integrity check can be bypassed.")

    while True:
        _print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            _run_add_file()
        elif choice == "2":
            _run_check_file()
        elif choice == "3":
            _run_check_all()
        elif choice == "4":
            _run_list_files()
        elif choice == "5":
            _run_remove_file()
        elif choice == "6":
            print("Leaving File Integrity Checker.")
            return
        else:
            print("Invalid choice. Enter 1, 2, 3, 4, 5, or 6.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
