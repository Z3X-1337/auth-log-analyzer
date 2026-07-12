"""Analyze OpenSSH-style authentication logs for defensive triage."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d).*sshd\[\d+\]: "
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
ACCEPTED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d).*sshd\[\d+\]: "
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    outcome: str
    user: str
    source_ip: str
    method: str | None = None
    invalid_user: bool = False


@dataclass(frozen=True)
class SuspiciousSource:
    source_ip: str
    failed_attempts: int
    accepted_logins: int
    targeted_users: list[str]
    invalid_user_attempts: int
    risk: str
    reasons: list[str]
    attack_techniques: list[dict[str, str]]


def _validated_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_line(line: str) -> AuthEvent | None:
    """Parse one supported OpenSSH authentication event."""

    failed = FAILED_RE.search(line)
    if failed:
        source_ip = _validated_ip(failed.group("ip"))
        if source_ip is None:
            return None
        return AuthEvent(
            timestamp=failed.group("timestamp"),
            outcome="failed",
            user=failed.group("user"),
            source_ip=source_ip,
            method=failed.group("method").lower(),
            invalid_user=failed.group("invalid") is not None,
        )

    accepted = ACCEPTED_RE.search(line)
    if accepted:
        source_ip = _validated_ip(accepted.group("ip"))
        if source_ip is None:
            return None
        return AuthEvent(
            timestamp=accepted.group("timestamp"),
            outcome="accepted",
            user=accepted.group("user"),
            source_ip=source_ip,
            method=accepted.group("method").lower(),
        )

    return None


def parse_events(lines: Iterable[str]) -> list[AuthEvent]:
    return [event for line in lines if (event := parse_line(line)) is not None]


def _validate_thresholds(failed_threshold: int, spray_threshold: int) -> None:
    if failed_threshold < 1:
        raise ValueError("failed_threshold must be at least 1")
    if spray_threshold < 1:
        raise ValueError("spray_threshold must be at least 1")


def _risk_for_source(
    failed_attempts: int,
    distinct_users: int,
    invalid_user_attempts: int,
    failed_threshold: int,
    spray_threshold: int,
) -> tuple[str, list[str]]:
    reasons: list[str] = []

    if failed_attempts >= failed_threshold:
        reasons.append(f"failed attempts >= {failed_threshold}")
    if distinct_users >= spray_threshold:
        reasons.append(f"distinct targeted users >= {spray_threshold}")
    if invalid_user_attempts > 0 and failed_attempts >= max(2, failed_threshold // 2):
        reasons.append("invalid users observed during repeated failures")

    if failed_attempts >= failed_threshold * 2 or distinct_users >= spray_threshold * 2:
        return "high", reasons
    if reasons:
        return "medium", reasons
    return "low", []


def _attack_mapping(distinct_users: int, spray_threshold: int) -> list[dict[str, str]]:
    techniques = [
        {
            "id": "T1110",
            "name": "Brute Force",
            "reason": "Repeated authentication failures were observed from one source.",
        }
    ]
    if distinct_users >= spray_threshold:
        techniques.append(
            {
                "id": "T1110.003",
                "name": "Password Spraying",
                "reason": "The source targeted multiple distinct usernames.",
            }
        )
    return techniques


def analyze_events(
    events: list[AuthEvent],
    failed_threshold: int = 5,
    spray_threshold: int = 3,
) -> dict:
    _validate_thresholds(failed_threshold, spray_threshold)

    failed_by_ip: Counter[str] = Counter()
    accepted_by_ip: Counter[str] = Counter()
    invalid_by_ip: Counter[str] = Counter()
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    methods_by_ip: dict[str, set[str]] = defaultdict(set)

    for event in events:
        users_by_ip[event.source_ip].add(event.user)
        if event.method:
            methods_by_ip[event.source_ip].add(event.method)
        if event.outcome == "failed":
            failed_by_ip[event.source_ip] += 1
            if event.invalid_user:
                invalid_by_ip[event.source_ip] += 1
        elif event.outcome == "accepted":
            accepted_by_ip[event.source_ip] += 1

    suspicious: list[SuspiciousSource] = []
    for source_ip in sorted(users_by_ip):
        failed_count = failed_by_ip[source_ip]
        accepted_count = accepted_by_ip[source_ip]
        invalid_count = invalid_by_ip[source_ip]
        targeted_users = sorted(users_by_ip[source_ip])
        risk, reasons = _risk_for_source(
            failed_count,
            len(targeted_users),
            invalid_count,
            failed_threshold,
            spray_threshold,
        )
        if risk != "low":
            suspicious.append(
                SuspiciousSource(
                    source_ip=source_ip,
                    failed_attempts=failed_count,
                    accepted_logins=accepted_count,
                    targeted_users=targeted_users,
                    invalid_user_attempts=invalid_count,
                    risk=risk,
                    reasons=reasons,
                    attack_techniques=_attack_mapping(len(targeted_users), spray_threshold),
                )
            )

    suspicious.sort(key=lambda item: (item.risk != "high", -item.failed_attempts, item.source_ip))

    return {
        "schema_version": "1.1",
        "summary": {
            "events_parsed": len(events),
            "failed_events": sum(failed_by_ip.values()),
            "accepted_events": sum(accepted_by_ip.values()),
            "unique_source_ips": len(users_by_ip),
            "suspicious_sources": len(suspicious),
        },
        "failed_by_ip": dict(sorted(failed_by_ip.items())),
        "accepted_by_ip": dict(sorted(accepted_by_ip.items())),
        "methods_by_ip": {ip: sorted(methods) for ip, methods in sorted(methods_by_ip.items())},
        "suspicious": [asdict(item) for item in suspicious],
        "limitations": [
            "Threshold detections are context-free and require analyst validation.",
            "Only supported OpenSSH accepted/failed authentication formats are parsed.",
            "Timestamps do not include a year or timezone and are preserved as raw evidence.",
        ],
    }


def analyze_lines(lines: Iterable[str], failed_threshold: int = 5, spray_threshold: int = 3) -> dict:
    return analyze_events(parse_events(lines), failed_threshold=failed_threshold, spray_threshold=spray_threshold)


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Authentication Log Analysis",
        "",
        "## Summary",
        "",
        f"- Events parsed: {summary['events_parsed']}",
        f"- Failed events: {summary['failed_events']}",
        f"- Accepted events: {summary['accepted_events']}",
        f"- Unique source IPs: {summary['unique_source_ips']}",
        f"- Suspicious sources: {summary['suspicious_sources']}",
        "",
        "## Suspicious Sources",
        "",
    ]

    if not report["suspicious"]:
        lines.append("No source crossed the configured thresholds.")
    else:
        for finding in report["suspicious"]:
            lines.extend(
                [
                    f"### {finding['source_ip']} — {finding['risk'].upper()}",
                    "",
                    f"- Failed attempts: {finding['failed_attempts']}",
                    f"- Accepted logins: {finding['accepted_logins']}",
                    f"- Targeted users: {', '.join(finding['targeted_users'])}",
                    f"- Reasons: {'; '.join(finding['reasons'])}",
                    f"- ATT&CK: {', '.join(item['id'] + ' ' + item['name'] for item in finding['attack_techniques'])}",
                    "",
                ]
            )

    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze OpenSSH-style authentication logs for suspicious login patterns.")
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--failed-threshold", type=int, default=5)
    parser.add_argument("--spray-threshold", type=int, default=3)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        lines = args.log_file.read_text(encoding="utf-8").splitlines()
        report = analyze_lines(lines, failed_threshold=args.failed_threshold, spray_threshold=args.spray_threshold)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))

    if args.format == "markdown":
        print(render_markdown(report))
    else:
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
