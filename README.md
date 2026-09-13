# CyberToolkit

A Python command-line toolkit for **learning defensive cybersecurity**. One program opens a menu. Each menu item is a small, local utility: passwords, hashing, file integrity, IP information, and log analysis.

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

1. **Password Analyzer** — Accepts a password without echoing it and reports its **length**. The password is not stored or sent anywhere. (Character-class scoring is not implemented yet.)
2. **Hash Calculator** — Hashes text or files with SHA-256, SHA-512, or educational MD5, and compares two hashes.
3. **File Integrity Checker** — Stores a SHA-256 baseline for local files and later reports unchanged, modified, or missing.
4. **IP Information Tool** — Validates IPv4/IPv6, classifies public/private/loopback/reserved, optional reverse DNS, and geo/ISP lookup for public IPs.
5. **Log Analyzer** — Reads a log line by line, counts events, searches keywords, extracts IPv4 addresses, and flags repeated failed logins as *potentially* suspicious.

## Technologies

| Technology | How it is used |
| --- | --- |
| Python 3 | Entire toolkit (standard library only) |
| Git / GitHub | Version control and publication |
| JSON | Integrity baselines (`data/monitored_files.json`) |
| Regular expressions | IPv4 extraction in the Log Analyzer |
| HTTPS / JSON APIs | Public IP lookup via [ipwho.is](https://ipwho.is/) |
| SHA-256 / SHA-512 / MD5 | Hashing and integrity |
| Terminal CLI | Main menu and each module |

No `pip` packages are required.

## Project structure

```text
CyberToolkit/
├── src/
│   ├── cybertool.py              # Main menu (start here)
│   ├── password_analyzer.py      # Part 1
│   ├── hash_calculator.py        # Part 2
│   ├── integrity_checker.py      # Part 3
│   ├── ip_information.py         # Part 4
│   └── log_analyzer.py           # Part 5
├── data/                         # Local integrity DB and optional IP reports
├── logs/
│   └── sample.log                # Example log for the analyzer
├── reports/                      # Optional log analysis reports
├── tests/                        # Unit tests
├── docs/                         # Extra notes (optional)
├── .gitignore
└── README.md
```

| Path | Role |
| --- | --- |
| `src/` | Application code. `cybertool.py` imports the other modules. |
| `data/` | Created/updated at runtime (integrity JSON, IP reports). Not for secrets. |
| `logs/` | Sample log plus any logs you choose to analyze. |
| `reports/` | Written only if you save a log report. |
| `tests/` | Automated tests for hashing, integrity, IP, logs, and the menu. |
| `docs/` | Placeholder for extra documentation. |

## Installation

**Requirement:** Python 3.10 or later (`python3 --version`).

```bash
git clone https://github.com/AljaziAlmujaddam/CyberToolkit.git
cd CyberToolkit
```

There is nothing to install with pip. Use the Python that shipped with macOS or your own Python 3.

## Usage

From the project folder:

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

## Modules

### Password Analyzer

Asks for a password with hidden input (`getpass`). Prints the character count. Nothing is saved, logged, or uploaded.

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

This project does not scan ports, exploit hosts, or hide activity.

## Testing

Automated tests (standard library `unittest`):

```bash
python3 tests/test_hash_calculator.py
python3 tests/test_integrity_checker.py
python3 tests/test_ip_information.py
python3 tests/test_log_analyzer.py
python3 tests/test_cybertool.py
```

| Area | Covered |
| --- | --- |
| Password Analyzer | Length helper; hidden input is manual |
| Hash Calculator | SHA-256/512, MD5 length, file hash, compare, invalid algorithm |
| File Integrity Checker | Add, unchanged, modified, missing, multiple files, remove |
| IP Information Tool | Valid/invalid IPs, types, mocked API errors, report save; private IPs not sent to the API |
| Log Analyzer | Sample log, empty log, missing file, failed-login threshold, IP counts, case-insensitive search |
| Main menu | All five tools are dispatched; `abc` and `9` rejected; Exit message |

Error handling includes empty input, missing files, directories, timeouts (IP tool), and permission errors where applicable.

## Learning objectives

This project was built to practice:

- Python programming (functions, modules, exceptions)
- File handling and JSON
- Hashing and file integrity
- IP addressing and HTTP APIs
- Regular expressions and log analysis
- CLI menus, input validation, and tests
- Git, `.gitignore`, and GitHub

## Future improvements

Not implemented yet:

- Richer password scoring and classifications
- Web UI or dashboard
- Real-time log monitoring and alerts
- Signed or protected integrity baselines
- Extra hash algorithms
- CSV/JSON exports
- Broader log formats (Apache, syslog, Windows Event Log)

## Disclaimer

CyberToolkit is a student / learning project. It is provided as-is for education. Do not rely on it to secure production systems, detect all attacks, or replace professional monitoring, antivirus, or incident-response tools.
