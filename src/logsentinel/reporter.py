"""Human-readable and JSON reporting."""
import json
from collections import Counter
from collections.abc import Iterable
from .models import Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 5), f.line_number, f.rule_id))


def to_json(findings: Iterable[Finding], *, source: str | None = None) -> str:
    ordered = sorted_findings(findings)
    payload = {
        "tool": "LogSentinel", "version": "0.1.0", "source": source,
        "summary": {"total_findings": len(ordered), "by_severity": dict(Counter(f.severity for f in ordered))},
        "findings": [f.to_dict() for f in ordered],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def to_text(findings: Iterable[Finding], *, source: str | None = None) -> str:
    ordered = sorted_findings(findings)
    counts = Counter(f.severity for f in ordered)
    lines = ["LogSentinel v0.1.0 — log analysis report", f"Source: {source or '(stdin or unknown)'}",
             f"Findings: {len(ordered)}"]
    if counts:
        lines.append("Severity: " + ", ".join(f"{key}={counts[key]}" for key in ("critical", "high", "medium", "low", "info") if counts[key]))
    lines.append("-" * 72)
    if not ordered:
        lines.append("No rule matches found. This does not prove the logs are benign.")
    for finding in ordered:
        location = f"line {finding.line_number}"
        if finding.timestamp:
            location += f", {finding.timestamp}"
        if finding.host:
            location += f", host={finding.host}"
        lines.extend([f"[{finding.severity.upper()}] {finding.rule_id} — {finding.title} ({location})",
                      f"  Match: {finding.matched_text}", f"  Why: {finding.description}",
                      f"  Next step: {finding.recommendation}", ""])
    lines.extend(["Note: findings are heuristic indicators for human review, not proof of compromise.",
                  "Input files are opened read-only; LogSentinel does not modify logs or access the network."])
    return "\n".join(lines) + "\n"
