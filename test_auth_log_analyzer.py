import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from auth_log_analyzer import analyze_events, analyze_lines, parse_events, parse_line, render_markdown


class AuthLogAnalyzerTests(unittest.TestCase):
    def test_parse_failed_invalid_user_event(self):
        event = parse_line("Jul 05 10:00:01 lab sshd[1001]: Failed password for invalid user admin from 203.0.113.10 port 50501 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "failed")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.source_ip, "203.0.113.10")
        self.assertEqual(event.method, "password")
        self.assertTrue(event.invalid_user)

    def test_parse_accepted_event(self):
        event = parse_line("Jul 05 10:01:10 lab sshd[1004]: Accepted publickey for analyst from 198.51.100.25 port 44992 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "accepted")
        self.assertEqual(event.method, "publickey")
        self.assertFalse(event.invalid_user)

    def test_parse_ipv6_and_failed_publickey(self):
        event = parse_line("Jul 05 10:01:10 lab sshd[1004]: Failed publickey for analyst from 2001:db8::10 port 44992 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "2001:db8::10")
        self.assertEqual(event.method, "publickey")

    def test_parse_events_ignores_unrelated_and_invalid_ip_lines(self):
        events = parse_events([
            "cron unrelated",
            "Jul 05 10:00:01 lab sshd[1001]: Failed password for root from not-an-ip port 1 ssh2",
            "Jul 05 10:00:01 lab sshd[1001]: Failed password for root from 203.0.113.10 port 1 ssh2",
        ])
        self.assertEqual(len(events), 1)

    def test_flags_repeated_failed_logins(self):
        lines = [
            "Jul 05 10:00:01 lab sshd[1]: Failed password for invalid user admin from 203.0.113.10 port 1 ssh2",
            "Jul 05 10:00:02 lab sshd[2]: Failed password for root from 203.0.113.10 port 2 ssh2",
            "Jul 05 10:00:03 lab sshd[3]: Failed password for user from 203.0.113.10 port 3 ssh2",
            "Jul 05 10:00:04 lab sshd[4]: Accepted publickey for analyst from 198.51.100.25 port 4 ssh2",
        ]
        report = analyze_lines(lines, failed_threshold=3)
        self.assertEqual(report["summary"]["events_parsed"], 4)
        self.assertEqual(report["summary"]["suspicious_sources"], 1)
        self.assertEqual(report["suspicious"][0]["source_ip"], "203.0.113.10")
        self.assertEqual(report["suspicious"][0]["risk"], "medium")
        self.assertEqual(report["suspicious"][0]["attack_techniques"][0]["id"], "T1110")

    def test_flags_password_spray_and_maps_subtechnique(self):
        lines = [
            f"Jul 05 10:00:0{i} lab sshd[{i}]: Failed password for user{i} from 203.0.113.20 port {i} ssh2"
            for i in range(1, 5)
        ]
        report = analyze_lines(lines, failed_threshold=10, spray_threshold=4)
        techniques = {item["id"] for item in report["suspicious"][0]["attack_techniques"]}
        self.assertIn("T1110.003", techniques)

    def test_high_risk_when_threshold_is_doubled(self):
        lines = [
            f"Jul 05 10:00:{i:02d} lab sshd[{i}]: Failed password for root from 203.0.113.30 port {i} ssh2"
            for i in range(10)
        ]
        report = analyze_lines(lines, failed_threshold=5)
        self.assertEqual(report["suspicious"][0]["risk"], "high")

    def test_analyze_events_counts_accepted_and_failed_by_ip(self):
        events = parse_events([
            "Jul 05 10:00:01 lab sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2",
            "Jul 05 10:00:02 lab sshd[2]: Accepted password for root from 203.0.113.10 port 2 ssh2",
        ])
        report = analyze_events(events, failed_threshold=1)
        self.assertEqual(report["failed_by_ip"]["203.0.113.10"], 1)
        self.assertEqual(report["accepted_by_ip"]["203.0.113.10"], 1)
        self.assertEqual(report["methods_by_ip"]["203.0.113.10"], ["password"])

    def test_rejects_non_positive_thresholds(self):
        with self.assertRaises(ValueError):
            analyze_lines([], failed_threshold=0)
        with self.assertRaises(ValueError):
            analyze_lines([], spray_threshold=0)

    def test_markdown_report_contains_evidence_and_limitations(self):
        report = analyze_lines([
            "Jul 05 10:00:01 lab sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2"
        ], failed_threshold=1)
        output = render_markdown(report)
        self.assertIn("# Authentication Log Analysis", output)
        self.assertIn("203.0.113.10", output)
        self.assertIn("T1110 Brute Force", output)
        self.assertIn("## Limitations", output)

    def test_cli_outputs_valid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "auth.log"
            sample.write_text("Jul 05 10:00:01 lab sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "auth_log_analyzer.py", str(sample), "--failed-threshold", "1"],
                check=True,
                capture_output=True,
                text=True,
            )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], "1.1")
        self.assertEqual(payload["summary"]["suspicious_sources"], 1)

    def test_cli_outputs_markdown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "auth.log"
            sample.write_text("Jul 05 10:00:01 lab sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "auth_log_analyzer.py", str(sample), "--failed-threshold", "1", "--format", "markdown"],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertTrue(result.stdout.startswith("# Authentication Log Analysis"))


if __name__ == "__main__":
    unittest.main()
