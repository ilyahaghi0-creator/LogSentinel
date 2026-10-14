"""Correlate repeated findings within a time window."""
from datetime import datetime, timedelta

from .models import CorrelationAlert, Finding

_WINDOW = timedelta(minutes=5)
_THRESHOLD = 5

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _parse_timestamp(value: str | None) -> datetime | None:
    """Accept ISO timestamps with an explicit timezone only."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed


def correlate(findings: list[Finding]) -> list[CorrelationAlert]:
    """Create one alert per continuous cluster containing a qualifying window."""
    groups: dict[str, list[tuple[datetime, Finding]]] = {}

    for finding in findings:
        timestamp = _parse_timestamp(finding.timestamp)
        if timestamp is not None:
            groups.setdefault(finding.rule_id, []).append((timestamp, finding))

    alerts: list[CorrelationAlert] = []

    for rule_id, entries in groups.items():
        entries.sort(key=lambda item: item[0])
        cluster: list[tuple[datetime, Finding]] = []
        alerted = False
        qualifying_window: tuple[datetime, datetime] | None = None

        for entry in entries:
            timestamp, _ = entry

            if cluster and timestamp - cluster[-1][0] > _WINDOW:
                if qualifying_window is not None:
                    alerts.append(
                        _build_alert(rule_id, cluster, qualifying_window)
                    )
                cluster = []
                alerted = False
                qualifying_window = None

            cluster.append(entry)

            window_entries = [
                item for item in cluster
                if timestamp - item[0] <= _WINDOW
            ]

            if len(window_entries) >= _THRESHOLD and not alerted:
                alerted = True
                qualifying_window = (
                    window_entries[0][0],
                    timestamp,
                )

        if qualifying_window is not None:
            alerts.append(_build_alert(rule_id, cluster, qualifying_window))

    alerts.sort(key=lambda alert: (alert.window_start, alert.rule_id))
    return alerts


def _build_alert(
    rule_id: str,
    cluster: list[tuple[datetime, Finding]],
    qualifying_window: tuple[datetime, datetime],
) -> CorrelationAlert:
    findings = tuple(finding for _, finding in cluster)
    window_start, window_end = qualifying_window

    severity = min(
        (finding.severity for finding in findings),
        key=lambda level: _SEVERITY_ORDER.get(level.lower(), 5),
    )

    return CorrelationAlert(
        correlation_id=(
            f"CORR-{rule_id}-{window_start.strftime('%Y%m%dT%H%M%S%f%z')}"
        ),
        rule_id=rule_id,
        title=f"Repeated activity detected: {findings[0].title}",
        severity=severity,
        event_count=len(findings),
        window_start=window_start.isoformat(),
        window_end=window_end.isoformat(),
        findings=findings,
        recommendation=(
            "Review the correlated events and surrounding logs; "
            "repeated indicators alone do not prove malicious activity."
        ),
    )
