# Auth Log Analyzer

Auth Log Analyzer is a defensive Python utility for reviewing SSH-style authentication logs and identifying suspicious login behavior.

It is designed for SOC learning labs, blue-team practice, and sanitized sample analysis.

## Detection Coverage

- Repeated failed logins from the same source IP.
- Password-spray style activity across multiple targeted usernames.
- Invalid user attempts during repeated authentication failures.
- Accepted login counts by source IP for context.

## Features

- Parses common OpenSSH `sshd` accepted and failed password log lines.
- Produces machine-readable JSON reports.
- Assigns medium or high risk based on configurable thresholds.
- Tracks targeted users and invalid user attempts.
- Uses only the Python standard library.

## Usage

```bash
python auth_log_analyzer.py sample_auth.log --pretty
python auth_log_analyzer.py sample_auth.log --failed-threshold 3 --spray-threshold 4 --pretty
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

## Run Tests

```bash
python -m unittest -v
```

## Continuous Integration

The repository includes a GitHub Actions workflow that runs the test suite on every push and pull request.

## Safety

Do not publish real production logs. Use sanitized examples that do not contain real users, hostnames, IP addresses, or private infrastructure details.
