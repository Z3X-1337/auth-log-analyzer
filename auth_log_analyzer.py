import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")


def parse_auth_log(lines: list[str], threshold: int = 5) -> dict:
    failed_by_ip: Counter[str] = Counter()
    accepted_by_ip: Counter[str] = Counter()
    users_by_ip: dict[str, set[str]] = defaultdict(set)

    for line in lines:
        failed = FAILED_RE.search(line)
        if failed:
            ip = failed.group("ip")
            failed_by_ip[ip] += 1
            users_by_ip[ip].add(failed.group("user"))
            continue

        accepted = ACCEPTED_RE.search(line)
        if accepted:
            ip = accepted.group("ip")
            accepted_by_ip[ip] += 1
            users_by_ip[ip].add(accepted.group("user"))

    suspicious = [
        {
            "ip": ip,
            "failed_attempts": count,
            "users_targeted": sorted(users_by_ip[ip]),
            "reason": f"failed attempts >= {threshold}",
        }
        for ip, count in failed_by_ip.items()
        if count >= threshold
    ]

    return {
        "failed_by_ip": dict(failed_by_ip),
        "accepted_by_ip": dict(accepted_by_ip),
        "suspicious": sorted(suspicious, key=lambda item: item["failed_attempts"], reverse=True),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze SSH-style authentication logs.")
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--threshold", type=int, default=5, help="Failed-login threshold for suspicious IPs.")
    args = parser.parse_args()

    lines = args.log_file.read_text(encoding="utf-8").splitlines()
    report = parse_auth_log(lines, threshold=args.threshold)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
