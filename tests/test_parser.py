import unittest
from logsentinel.parser import parse_lines

class ParserTests(unittest.TestCase):
    def test_plain_line_and_line_numbers(self):
        events = list(parse_lines(["first\n", "\n", "third\n"]))
        self.assertEqual([e.line_number for e in events], [1, 3])
        self.assertEqual(events[0].source_format, "plain")

    def test_syslog(self):
        event = list(parse_lines(["Oct 14 12:34:56 host sshd[123]: Failed password for root from 192.0.2.1\n"]))[0]
        self.assertEqual(event.host, "host")
        self.assertEqual(event.service, "sshd")
        self.assertEqual(event.pid, 123)
        self.assertIn("Failed password", event.message)

    def test_json_line(self):
        event = list(parse_lines(['{"timestamp":"2026-10-14T10:00:00Z","host":"node1","service":"sshd","message":"Invalid user guest"}\n']))[0]
        self.assertEqual(event.source_format, "json")
        self.assertEqual(event.host, "node1")
        self.assertEqual(event.timestamp, "2026-10-14T10:00:00Z")

    def test_invalid_json_falls_back_to_plain(self):
        event = list(parse_lines(['{"message": broken}\n']))[0]
        self.assertEqual(event.source_format, "plain")

if __name__ == "__main__":
    unittest.main()
