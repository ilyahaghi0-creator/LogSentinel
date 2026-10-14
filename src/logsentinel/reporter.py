
"""Human-readable and JSON reporting."""
import json
from collections import Counter
from collections.abc import Iterable

from .models import CorrelationAlert, Finding

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity.lower(), 5),
            f.line_number,
            f.rule_id,
        ),
    )


def _sorted_alerts(
    alerts: Iterable[CorrelationAlert],
) -> list[CorrelationAlert]:
    return sorted(
        alerts,
        key=lambda alert: (alert.window_start, alert.rule_id),
    )


def to_json(
    findings: Iterable[Finding],
    *,
    source: str | None = None,
    correlation_alerts: Iterable[CorrelationAlert] | None = None,
) -> str:
    ordered = sorted_findings(findings)
    payload = {
        "tool": "LogSentinel",
        "version": "0.1.0",
        "source": source,
        "summary": {
            "total_findings": len(ordered),
            "by_severity": dict(Counter(f.severity for f in ordered)),
        },
        "findings": [f.to_dict() for f in ordered],
    }

    if correlation_alerts is not None:
        alerts = _sorted_alerts(correlation_alerts)
        payload["summary"]["total_correlation_alerts"] = len(alerts)
        payload["correlation_alerts"] = [
            alert.to_dict() for alert in alerts
        ]

    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def to_text(
    findings: Iterable[Finding],
    *,
    source: str | None = None,
    correlation_alerts: Iterable[CorrelationAlert] | None = None,
) -> str:
    ordered = sorted_findings(findings)
    counts = Counter(f.severity for f in ordered)

    lines = [
        "LogSentinel v0.1.0 — log analysis report",
        f"Source: {source or '(stdin or unknown)'}",
        f"Findings: {len(ordered)}",
    ]

    if counts:
        lines.append(
            "Severity: "
            + ", ".join(
                f"{key}={counts[key]}"
                for key in ("critical", "high", "medium", "low", "info")
                if counts[key]
            )
        )

    lines.append("-" * 72)

    if not ordered:
        lines.append(
            "No rule matches found. This does not prove the logs are benign."
        )

    for finding in ordered:
        location = f"line {finding.line_number}"
        if finding.timestamp:
            location += f", {finding.timestamp}"
        if finding.host:
            location += f", host={finding.host}"

        lines.extend([
            f"[{finding.severity.upper()}] {finding.rule_id} — "
            f"{finding.title} ({location})",
            f"  Match: {finding.matched_text}",
            f"  Why: {finding.description}",
            f"  Next step: {finding.recommendation}",
            "",
        ])

    if correlation_alerts is not None:
        alerts = _sorted_alerts(correlation_alerts)
        lines.extend([
            "-" * 72,
            f"Correlation alerts: {len(alerts)}",
        ])

        for alert in alerts:
            lines.extend([
                f"[{alert.severity.upper()}] {alert.correlation_id} — "
                f"{alert.title}",
                f"  Rule: {alert.rule_id}",
                f"  Events: {alert.event_count}",
                f"  Window: {alert.window_start} → {alert.window_end}",
                f"  Next step: {alert.recommendation}",
                "",
            ])

        if not alerts:
            lines.append("No correlation patterns met the configured threshold.")

    lines.extend([
        "Note: findings are heuristic indicators for human review, "
        "not proof of compromise.",
        "Input files are opened read-only; LogSentinel does not modify logs "
        "or access the network.",
    ])

    return "\n".join(lines) + "\n"
