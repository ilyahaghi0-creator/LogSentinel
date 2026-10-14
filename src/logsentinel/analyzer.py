"""Apply rules to parsed log events."""
from collections.abc import Iterable
from .models import Finding, LogEvent
from .rules import Rule


def analyze(events: Iterable[LogEvent], rules: Iterable[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    rule_list = list(rules)
    for event in events:
        # Search the full raw line as well as the parsed message so structured metadata
        # can be detected while preserving the original line for analyst review.
        haystack = event.raw
        for rule in rule_list:
            match = rule.pattern.search(haystack)
            if match:
                findings.append(Finding(
                    rule_id=rule.rule_id, title=rule.title, severity=rule.severity,
                    description=rule.description, line_number=event.line_number,
                    matched_text=match.group(0), recommendation=rule.recommendation,
                    timestamp=event.timestamp, host=event.host, service=event.service,
                ))
    return findings
