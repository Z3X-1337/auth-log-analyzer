# Auth Log Analyzer

[![tests](https://github.com/Z3X-1337/auth-log-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Z3X-1337/auth-log-analyzer/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.10--3.12-blue)
![Version](https://img.shields.io/badge/version-0.1.0-informational)
![License](https://img.shields.io/badge/license-MIT-green)

Auth Log Analyzer is a deterministic Python command-line utility for reviewing supported OpenSSH authentication events and identifying suspicious login behavior.

It is designed for SOC learning labs, sanitized incident-analysis exercises, and explainable detection engineering. It is not a replacement for a SIEM, EDR, or analyst validation.

## Detection Coverage

- Repeated authentication failures from the same source IP.
- Password-spray-style activity across multiple targeted usernames.
- Invalid-user attempts during repeated failures.
- Accepted login counts by source IP for investigation context.
- IPv4 and IPv6 source addresses.
- Supported failed methods: `password`, `publickey`, and `keyboard-interactive/pam`.

## Analyst-Focused Output

- Machine-readable JSON with schema versioning.
- Markdown reports for tickets and case notes.
- Detection reasons and configured thresholds.
- Authentication methods observed by source.
- Evidence-based MITRE ATT&CK suggestions:
  - `T1110` — Brute Force.
  - `T1110.003` — Password Spraying when multiple accounts are targeted.
- Explicit limitations requiring analyst review.

## Installation

Install from a local clone:

```bash
python -m pip install .
```

For an isolated CLI installation:

```bash
pipx install .
```

The installed command is:

```bash
auth-log-analyzer --help
```

## Usage

```bash
auth-log-analyzer sample_auth.log --pretty
auth-log-analyzer sample_auth.log --failed-threshold 3 --spray-threshold 4 --pretty
auth-log-analyzer sample_auth.log --format markdown
```

The source-file form remains supported:

```bash
python auth_log_analyzer.py sample_auth.log --pretty
```

## Example Summary

```json
{
  "accepted_events": 1,
  "events_parsed": 5,
  "failed_events": 4,
  "suspicious_sources": 1,
  "unique_source_ips": 2
}
```

## Validation

```bash
python -m unittest -v
```

The current suite contains 12 unit and CLI tests covering parsing, IPv6, authentication methods, threshold validation, risk classification, ATT&CK mapping, JSON output, and Markdown output.

GitHub Actions tests Python 3.10, 3.11, and 3.12, installs the package, and verifies the CLI entry point.

## Project Governance

- [Changelog](CHANGELOG.md)
- [Roadmap](ROADMAP.md)
- [MIT License](LICENSE)

The current package version is `0.1.0` and follows Semantic Versioning.

## Limitations

- Threshold detections are context-free and can produce false positives.
- Only documented OpenSSH accepted/failed formats are parsed.
- Syslog timestamps are retained as raw evidence and do not include a year or timezone.
- ATT&CK entries are analyst-assistance suggestions, not proof of adversary intent.

## Safety

Do not publish real production logs, usernames, hostnames, credentials, IP addresses, or private infrastructure details. Use sanitized examples and data you are authorized to analyze.
