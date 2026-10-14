import json
import unittest
from logsentinel.analyzer import analyze
from logsentinel.parser import parse_lines
from logsentinel.reporter import to_json, to_text
from logsentinel.rules import builtin_rules

class ReporterTests(unittest.TestCase):
    def test_json_report_is_valid(self):
        findings = analyze(parse_lines(["Failed password for root\n"]), builtin_rules())
        payload = json.loads(to_json(findings, source="test.log"))
        self.assertEqual(payload["summary"]["total_findings"], 1)
        self.assertEqual(payload["source"], "test.log")

    def test_empty_text_report_is_honest(self):
        report = to_text([], source="empty.log")
        self.assertIn("No rule matches found", report)
        self.assertIn("does not prove", report)

if __name__ == "__main__":
    unittest.main()
