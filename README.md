# Auth Log Analyzer

Analyze SSH-style authentication logs and highlight suspicious login patterns.

This project is a defensive blue-team tool for learning how basic log detection works.

## Features

- Parses failed password attempts.
- Parses accepted logins.
- Counts activity by source IP.
- Flags repeated failed logins from the same IP.
- Runs without third-party dependencies.

## Usage

```bash
python auth_log_analyzer.py sample_auth.log --threshold 3
```

## Run Tests

```bash
python -m unittest test_auth_log_analyzer.py
```

## Safety Note

Do not upload real production logs to a public repository. Use sanitized samples only.
