
import unittest
from datetime import datetime, timedelta, timezone

from logsentinel.correlator import correlate
from logsentinel.models import Finding


BASE = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)


def make_finding(
    minute,
    rule_id="AUTH-001",
    line_number=1,
    timestamp_override=None,
):
    timestamp = (
        timestamp_override
        if timestamp_override is not None
        else (BASE + timedelta(minutes=minute)).isoformat()
    )

    return Finding(
        rule_id=rule_id,
        title="Authentication failure",
        severity="medium",
        description="Authentication failed.",
        line_number=line_number,
        matched_text="Failed password",
        recommendation="Review authentication logs.",
        timestamp=timestamp,
    )


class CorrelatorTests(unittest.TestCase):
    def test_four_findings_do_not_trigger_alert(self):
        findings = [make_finding(i, line_number=i + 1) for i in range(4)]
        self.assertEqual(correlate(findings), [])

    def test_five_findings_within_five_minutes_trigger_alert(self):
        findings = [make_finding(i, line_number=i + 1) for i in range(5)]
        alerts = correlate(findings)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 5)
        self.assertEqual(alerts[0].rule_id, "AUTH-001")

    def test_five_findings_without_qualifying_window_do_not_alert(self):
        minutes = [0, 1, 2, 6, 7]
        findings = [
            make_finding(m, line_number=i + 1)
            for i, m in enumerate(minutes)
        ]
        self.assertEqual(correlate(findings), [])

    def test_different_rules_are_not_correlated(self):
        findings = [
            make_finding(i, rule_id=f"RULE-{i}", line_number=i + 1)
            for i in range(5)
        ]
        self.assertEqual(correlate(findings), [])

    def test_invalid_and_timezone_naive_timestamps_are_ignored(self):
        findings = [
            make_finding(i, line_number=i + 1)
            for i in range(4)
        ]
        findings.append(
            make_finding(
                4,
                line_number=5,
                timestamp_override="not-a-timestamp",
            )
        )
        findings.append(
            make_finding(
                4,
                line_number=6,
                timestamp_override="2026-10-14T10:04:00",
            )
        )

        self.assertEqual(correlate(findings), [])

    def test_seven_findings_in_one_cluster_make_one_alert(self):
        findings = [make_finding(i, line_number=i + 1) for i in range(7)]
        alerts = correlate(findings)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 7)

    def test_separate_clusters_make_separate_alerts(self):
        minutes = list(range(5)) + list(range(20, 25))
        findings = [
            make_finding(m, line_number=i + 1)
            for i, m in enumerate(minutes)
        ]

        alerts = correlate(findings)

        self.assertEqual(len(alerts), 2)
        self.assertEqual([a.event_count for a in alerts], [5, 5])

    def test_unsorted_input_still_correlates(self):
        findings = [
            make_finding(i, line_number=i + 1)
            for i in [4, 1, 3, 0, 2]
        ]
        self.assertEqual(len(correlate(findings)), 1)

    def test_original_findings_are_preserved(self):
        findings = [make_finding(i, line_number=i + 1) for i in range(5)]
        original = findings.copy()

        correlate(findings)

        self.assertEqual(findings, original)
        self.assertEqual(len(findings), 5)

    def test_empty_input_returns_no_alerts(self):
        self.assertEqual(correlate([]), [])
    def test_alert_ids_are_unique_for_separate_clusters(self):
        minutes = list(range(5)) + list(range(20, 25))
        findings = [
            make_finding(m, line_number=i + 1)
            for i, m in enumerate(minutes)
        ]

        alerts = correlate(findings)

        ids = [alert.correlation_id for alert in alerts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_alert_window_is_five_minutes_or_less(self):
        findings = [
            make_finding(i, line_number=i + 1)
            for i in range(5)
        ]
        alerts = correlate(findings)

        self.assertEqual(len(alerts), 1)

        start = datetime.fromisoformat(alerts[0].window_start)
        end = datetime.fromisoformat(alerts[0].window_end)

        self.assertLessEqual(end - start, timedelta(minutes=5))
        self.assertEqual(alerts[0].event_count, 5)

if __name__ == "__main__":
    unittest.main()
