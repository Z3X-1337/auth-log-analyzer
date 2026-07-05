import unittest

from auth_log_analyzer import parse_auth_log


class AuthLogAnalyzerTests(unittest.TestCase):
    def test_flags_repeated_failed_logins(self):
        lines = [
            "Failed password for invalid user admin from 203.0.113.10 port 1 ssh2",
            "Failed password for root from 203.0.113.10 port 2 ssh2",
            "Failed password for user from 203.0.113.10 port 3 ssh2",
            "Accepted publickey for analyst from 198.51.100.25 port 4 ssh2",
        ]
        report = parse_auth_log(lines, threshold=3)
        self.assertEqual(report["failed_by_ip"]["203.0.113.10"], 3)
        self.assertEqual(report["accepted_by_ip"]["198.51.100.25"], 1)
        self.assertEqual(report["suspicious"][0]["ip"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
