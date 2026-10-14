import json
import unittest

from logsentinel.analyzer import analyze
from logsentinel.correlator import correlate
from logsentinel.parser import parse_lines
from logsentinel.reporter import to_json, to_text
from logsentinel.rules import builtin_rules


class ReporterTests(unittest.TestCase):
    def test_json_report_is_valid(self):
        findings = analyze(
            parse_lines(["Failed password for root\n"]),
            builtin_rules(),
        )
        payload = json.loads(to_json(findings, source="test.log"))
        self.assertEqual(payload["summary"]["total_findings"], 1)
        self.assertEqual(payload["source"], "test.log")

    def test_empty_text_report_is_honest(self):
        report = to_text([], source="empty.log")
        self.assertIn("No rule matches found", report)
        self.assertIn("does not prove", report)

    def test_json_report_includes_correlation_alerts(self):
        lines = [
            f"2026-10-14T10:0{i}:00Z host sshd: Failed password for root\n"
            for i in range(5)
        ]
        findings = analyze(parse_lines(lines), builtin_rules())
        alerts = correlate(findings)

        payload = json.loads(
            to_json(
                findings,
                source="test.log",
                correlation_alerts=alerts,
            )
        )

        self.assertEqual(payload["summary"]["total_correlation_alerts"], 1)
        self.assertEqual(len(payload["correlation_alerts"]), 1)
        self.assertEqual(payload["correlation_alerts"][0]["event_count"], 5)

    def test_text_report_includes_correlation_alerts(self):
        lines = [
            f"2026-10-14T10:0{i}:00Z host sshd: Failed password for root\n"
            for i in range(5)
        ]
        findings = analyze(parse_lines(lines), builtin_rules())
        alerts = correlate(findings)

        report = to_text(
            findings,
            source="test.log",
            correlation_alerts=alerts,
        )

        self.assertIn("Correlation alerts: 1", report)
        self.assertIn("CORR-AUTH-001", report)
        self.assertIn("Events: 5", report)


if __name__ == "__main__":
    unittest.main()
