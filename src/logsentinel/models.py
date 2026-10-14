"""Small typed data models used by the parser and analyzer."""
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True, slots=True)
class LogEvent:
    line_number: int
    raw: str
    message: str
    timestamp: str | None = None
    host: str | None = None
    service: str | None = None
    pid: int | None = None
    level: str | None = None
    source_format: str = "plain"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    line_number: int
    matched_text: str
    recommendation: str
    timestamp: str | None = None
    host: str | None = None
    service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True, slots=True)
class CorrelationAlert:
    correlation_id: str
    rule_id: str
    title: str
    severity: str
    event_count: int
    window_start: str
    window_end: str
    findings: tuple[Finding, ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "event_count": self.event_count,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "findings": [finding.to_dict() for finding in self.findings],
            "recommendation": self.recommendation,
        }
