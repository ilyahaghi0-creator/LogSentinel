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
