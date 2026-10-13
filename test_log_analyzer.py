import unittest

from log_analyzer import analyze, valid_ipv4


class LogAnalyzerTests(unittest.TestCase):
    def test_flags_ip_at_threshold(self):
        lines = [
            "Failed password for alice from 203.0.113.5 port 1 ssh2",
            "Failed password for bob from 203.0.113.5 port 2 ssh2",
            "Failed password for invalid user root from 203.0.113.5 port 3 ssh2",
        ]
        result = analyze(lines, threshold=3)
        self.assertEqual(result["repeated_failures"], [{"ip": "203.0.113.5", "failed_attempts": 3}])
        self.assertEqual(result["summary"]["failed_logins"], 3)

    def test_counts_successful_login(self):
        result = analyze(["Accepted publickey for user from 192.0.2.10 port 4 ssh2"])
        self.assertEqual(result["summary"]["successful_logins"], 1)

    def test_rejects_invalid_ipv4(self):
        self.assertFalse(valid_ipv4("999.1.1.1"))
        self.assertFalse(valid_ipv4("1.2.3"))
        self.assertTrue(valid_ipv4("203.0.113.8"))


if __name__ == "__main__":
    unittest.main()
