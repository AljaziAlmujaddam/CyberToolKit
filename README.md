# CyberToolkit

A Python toolkit for **learning defensive cybersecurity**.

- **Version 1** is a terminal menu (`src/cybertool.py`).
- **Version 2** is a local Flask web app (`run.py`) that will reuse the same Python modules from a browser.

**Purpose:** education and authorized practice on your own machine. This is not a production security product and does not replace professional tools.

## Overview

CyberToolkit helps you practice:

- Python modules, functions, and a menu-driven CLI
- File handling and JSON
- Cryptographic hashes and integrity checks
- IP addressing and a public HTTPS lookup API
- Regular expressions and basic log analysis
- Error handling, tests, Git, and GitHub

All tools run locally except the IP Information Tool, which may send a **public** IP address to an external API when you look it up.

## Features

1. **Password Analyzer** — Accepts a password without echoing it and reports **length**, character classes (upper, lower, digit, special), and a simple **strength** label. The password is not stored or sent anywhere.
2. **Hash Calculator** — Hashes text or files with SHA-256, SHA-512, or educational MD5, and compares two hashes.
3. **File Integrity Checker** — Stores a SHA-256 baseline for local files and later reports unchanged, modified, or missing.
4. **IP Information Tool** — Validates IPv4/IPv6, classifies public/private/loopback/reserved, optional reverse DNS, and geo/ISP lookup for public IPs.
5. **Log Analyzer** — Reads a log line by line, counts events, searches keywords, extracts IPv4 addresses, and flags repeated failed logins as *potentially* suspicious.

## Technologies

| Technology | How it is used |
| --- | --- |
| Python 3 | Entire toolkit |
| Flask | Version 2 local web server and routes |
| HTML / CSS / JavaScript | Version 2 homepage (no security algorithms in JS) |
| Git / GitHub | Version control and publication |
| JSON | Integrity baselines (`data/monitored_files.json`) |
| Regular expressions | IPv4 extraction in the Log Analyzer |
| HTTPS / JSON APIs | Public IP lookup via [ipwho.is](https://ipwho.is/) |
| SHA-256 / SHA-512 / MD5 | Hashing and integrity |
| Terminal CLI | Version 1 main menu and each module |

Version 1 uses the Python standard library only. Version 2 also needs Flask (`requirements.txt`).

## Project structure

```text
CyberToolkit/
├── app/                          # Version 2 Flask application
│   ├── __init__.py
│   ├── routes.py
│   ├── modules/                  # Thin wrappers around src/ (logic not rewritten)
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/style.css
│       └── js/app.js
├── src/                          # Version 1 CLI and cybersecurity modules
│   ├── cybertool.py
│   ├── password_analyzer.py
│   ├── hash_calculator.py
│   ├── integrity_checker.py
│   ├── ip_information.py
│   └── log_analyzer.py
├── data/
├── logs/
│   └── sample.log
├── reports/
├── tests/
├── docs/
├── run.py                        # Start the Version 2 web app
├── requirements.txt
├── .gitignore
└── README.md
```

| Path | Role |
| --- | --- |
| `src/` | Version 1. `cybertool.py` and the security modules. **Do not delete.** |
| `app/` | Version 2 Flask app. Dashboard UI plus JSON APIs (`/api/status`, first tool route). |
| `app/modules/` | Imports V1 functions so the web app can call them later. |
| `data/` | Created/updated at runtime (integrity JSON, IP reports). Not for secrets. |
| `logs/` | Sample log plus any logs you choose to analyze. |
| `reports/` | Written only if you save a log report. |
| `tests/` | Automated tests for V1 tools and the V2 homepage. |
| `docs/` | Placeholder for extra documentation. |

## Installation

**Requirement:** Python 3.10 or later (`python3 --version`).

```bash
git clone https://github.com/AljaziAlmujaddam/CyberToolkit.git
cd CyberToolkit
```

**Version 1 (CLI)** needs no pip packages.

**Version 2 (web)** uses a virtual environment and Flask:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The `.venv/` folder is gitignored and should not be uploaded to GitHub.

## Usage

### Version 1 — terminal

```bash
python3 src/cybertool.py
```

```text
========================================
           CYBERTOOLKIT
========================================

1. Password Analyzer
2. Hash Calculator
3. File Integrity Checker
4. IP Information Tool
5. Log Analyzer
6. Exit

Select an option:
```

Enter `1`–`5` to open a tool. Use **Back** inside a tool, then Enter, to return to this menu. Enter `6` to quit.

You can still run a module directly while learning, for example `python3 src/hash_calculator.py`.

### Version 2 — local web dashboard (Part 6)

The homepage is a full dashboard. All five Version 1 tools work through Flask: **Password Analyzer**, **Hash Calculator** (text hashing), **File Integrity Checker**, **IP Information**, and **Log Analyzer**.

```bash
source .venv/bin/activate
python3 run.py
```

Then open [http://127.0.0.1:5000/](http://127.0.0.1:5000/) on the same computer. The server binds to localhost only.

```text
Browser  →  HTML / CSS / JS  →  HTTP  →  Flask  →  V1 Python modules  →  JSON  →  Dashboard
```

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Dashboard |
| GET | `/api/status` | JSON health check |
| POST | `/api/password/analyze` | Password analysis (not stored or echoed) |
| POST | `/api/hash/calculate` | Text hash (`sha256`, `sha512`, or educational `md5`) |
| POST | `/api/integrity/register` | Upload a file into `data/monitored/` and store its SHA-256 |
| POST | `/api/integrity/check` | Compare a file in that folder with its stored hash |
| GET | `/api/integrity/files` | List registered names (no absolute server paths) |
| POST | `/api/integrity/check-all` | Check every registered file in the allowed folder |
| POST | `/api/ip/analyze` | Validate/classify an IP; public IPs may be looked up at ipwho.is |
| GET | `/api/log/files` | List files in `logs/` |
| POST | `/api/log/analyze` | Analyze an upload or a file from `logs/` (local only) |
| POST | `/api/log/search` | Case-insensitive keyword search of the same authorized log |

Web integrity and log tools never accept arbitrary paths such as `/etc/passwd` or `../`. Uploaded logs are size-limited, scanned as text, analyzed locally, and not kept after the request. Optional `IPWHO_API_KEY` is read from the environment only. Private, loopback, and reserved IPs are not sent to the external API. Repeated failed logins are labeled *potentially suspicious*, not as proof of an attack.

## Modules

### Password Analyzer

Asks for a password with hidden input (`getpass`). Reports length, whether it contains uppercase, lowercase, digits, and special characters, then a simple strength label (Very Weak / Weak / Medium / Strong) with short suggestions. The password is never printed, saved, logged, or uploaded. This is an educational checker — it does not look up leaked passwords.

### Hash Calculator

- **SHA-256** — default modern digest for this project
- **SHA-512** — longer digest in the same family
- **MD5** — educational comparison only; MD5 is cryptographically broken

Hash text or a local file (read in chunks, read-only). Compare two hex hashes with `hmac.compare_digest`.

### File Integrity Checker

1. Add a file → compute SHA-256 → store path + hash in `data/monitored_files.json`
2. Check later → compare current hash to the stored hash

Statuses: unchanged, modified, missing, not registered, unreadable. File **contents** are never stored. The monitored file is never written by this tool.

If someone can change **both** the file and the JSON baseline, they can hide a change. That is a limit of this educational design.

### IP Information Tool

Validates the address, shows IPv4 vs IPv6, and type (Public, Private, Loopback, Reserved). Reverse DNS uses the local resolver; “Not available” is normal.

**Public** IPs are looked up over HTTPS at ipwho.is. Private, loopback, and reserved addresses are **not** sent to the API. Lookups are not saved unless you choose Save Report (`data/IP_Report_<ip>.txt`).

No API key is hard-coded. A keyed plan would use the `IPWHO_API_KEY` environment variable.

### Log Analyzer

Reads a log you choose, line by line. Counts INFO / WARNING / ERROR, failed and successful login phrases, extracts IPv4 addresses, and treats **3 or more failed logins from one IP** as potentially suspicious — not proof of an attack.

Try `logs/sample.log`. Keyword search is case-insensitive. Save Report writes `reports/Log_Analysis_Report.txt` and does not change the original log.

## Security considerations

- Educational and **authorized, local** use only. Do not analyze systems or logs you are not allowed to access.
- Passwords are not stored.
- Tools do not modify user files except when you explicitly save a report or update the integrity JSON.
- Logs and integrity baselines can contain sensitive paths and IPs. Treat them as sensitive.
- Public IP lookup **shares that IP** with the API provider.
- Simple log rules produce **false positives**.
- **Do not use MD5** for password storage or security-critical integrity.
- Do not commit API keys, tokens, or `.env` files.
- Run the Flask development server on **localhost** (`127.0.0.1`). Do not expose it to the internet.
- Do not put a Flask secret key in source control; use `FLASK_SECRET_KEY` if sessions are added later.
- The web UI must never execute shell commands or untrusted code from the browser.
- Passwords entered into the analyzer must not be stored (V1 already follows this).

This project does not scan ports, exploit hosts, or hide activity.

## Testing

Version 2 tests need Flask installed (use the virtual environment):

```bash
source .venv/bin/activate
python3 tests/test_web_app.py
```

```bash
python3 tests/test_password_analyzer.py
python3 tests/test_hash_calculator.py
python3 tests/test_integrity_checker.py
python3 tests/test_ip_information.py
python3 tests/test_log_analyzer.py
python3 tests/test_cybertool.py
python3 tests/test_web_app.py
```

| Area | Covered |
| --- | --- |
| Password Analyzer | Length, character classes, strength labels; hidden input is manual |
| Hash Calculator | SHA-256/512, MD5 length, file hash, compare, invalid algorithm |
| File Integrity Checker | Add, unchanged, modified, missing, multiple files, remove |
| IP Information Tool | Valid/invalid IPs, types, mocked API errors, report save; private IPs not sent to the API |
| Log Analyzer | Sample log, empty log, missing file, failed-login threshold, IP counts, case-insensitive search |
| Main menu | All five tools are dispatched; `abc` and `9` rejected; Exit message |
| Version 2 homepage and API | All five tools; path traversal rejected; private IPs not sent to the API; logs analyzed locally; V1 helpers still import |

Error handling includes empty input, missing files, directories, timeouts (IP tool), and permission errors where applicable.

## Learning objectives

This project was built to practice:

- Python programming (functions, modules, exceptions)
- File handling and JSON
- Hashing and file integrity
- IP addressing and HTTP APIs
- Regular expressions and log analysis
- CLI menus, input validation, and tests
- Flask, HTML/CSS/JavaScript, and frontend/backend separation
- Git, `.gitignore`, and GitHub

## Future improvements

Not implemented yet:

- File hashing and hash comparison in the web Hash Calculator
- Common-password / breach checks (still never store the password)
- Real-time log monitoring and alerts
- Signed or protected integrity baselines
- Extra hash algorithms
- CSV/JSON exports
- Broader log formats (Apache, syslog, Windows Event Log)

## Disclaimer

CyberToolkit is a student / learning project. It is provided as-is for education. Do not rely on it to secure production systems, detect all attacks, or replace professional monitoring, antivirus, or incident-response tools.
