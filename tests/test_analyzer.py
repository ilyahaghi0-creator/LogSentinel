import tempfile
import unittest
from pathlib import Path
from logsentinel.analyzer import analyze
from logsentinel.parser import parse_lines
from logsentinel.rules import builtin_rules, load_rules

class AnalyzerTests(unittest.TestCase):
    def test_auth_failure_detected(self):
        events = parse_lines(["Oct 14 12:34:56 node sshd[44]: Failed password for admin from 203.0.113.5\n"])
        findings = analyze(events, builtin_rules())
        self.assertTrue(any(f.rule_id == "AUTH-001" for f in findings))
        self.assertEqual(findings[0].line_number, 1)

    def test_benign_line_no_match(self):
        self.assertEqual(analyze(parse_lines(["system started normally\n"]), builtin_rules()), [])

    def test_custom_rule(self):
        payload = '[{"id":"CUSTOM-1","title":"Test marker","severity":"info","pattern":"ALERT_TEST","description":"test","recommendation":"review"}]'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(payload, encoding="utf-8")
            rules = load_rules(path)
        findings = analyze(parse_lines(["ALERT_TEST\n"]), rules)
        self.assertTrue(any(f.rule_id == "CUSTOM-1" for f in findings))

    def test_duplicate_custom_id_rejected(self):
        payload = '[{"id":"AUTH-001","title":"x","severity":"info","pattern":"x","description":"x","recommendation":"x"}]'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(payload, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules(path)

if __name__ == "__main__":
    unittest.main()
