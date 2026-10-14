"""Built-in and user-defined detection rules."""
from __future__ import annotations
from dataclasses import dataclass
import json
import re
from pathlib import Path

@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    recommendation: str


def _rule(rule_id: str, title: str, severity: str, pattern: str, description: str, recommendation: str) -> Rule:
    return Rule(rule_id, title, severity, re.compile(pattern, re.IGNORECASE), description, recommendation)


def builtin_rules() -> list[Rule]:
    """Return conservative indicators; matches are leads for review, not proof of attack."""
    return [
        _rule("AUTH-001", "Authentication failure", "medium",
              r"\b(?:failed password|authentication failure|auth(?:entication)? failed|invalid user|login failed|failed login)\b",
              "A log message indicates an unsuccessful authentication attempt.",
              "Check source addresses, target accounts, and surrounding events; correlate repeated failures before concluding brute force."),
        _rule("AUTH-002", "Repeated authentication failures", "high",
              r"\b(?:too many authentication failures|maximum authentication attempts exceeded|PAM.*(?:failure|failed))\b",
              "The message suggests multiple authentication failures or an authentication limit being reached.",
              "Review nearby events and account activity. Use a time-windowed correlation to confirm a pattern; this rule alone does not count attempts."),
        _rule("PRIV-001", "Privilege-related activity", "low",
              r"\b(?:sudo:|su:.*session opened|privilege escalation)\b",
              "The log contains a common marker for privileged command or account activity.",
              "Verify the user, command, time, and authorization against expected administrative activity."),
        _rule("SERVICE-001", "Service or process failure", "low",
              r"\b(?:segmentation fault|core dumped|failed to start|service .* failed|process .* exited with (?:status|code) [1-9])\b",
              "A service or process may have failed.",
              "Inspect the service's surrounding logs and system health; failures can be routine and are not necessarily security incidents."),
        _rule("SEC-001", "Potential security-control change", "medium",
              r"\b(?:firewall disabled|iptables.*(?:flush|delete)|auditd stopped|selinux.*disabled|apparmor.*disabled|security policy.*(?:changed|disabled))\b",
              "The message may indicate a security control was disabled or changed.",
              "Confirm whether the change was approved and review privileged activity around the same time."),
    ]


def load_rules(path: str | Path | None = None) -> list[Rule]:
    rules = builtin_rules()
    if path is None:
        return rules
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load rules file: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError("custom rules file must contain a JSON array")
    existing = {rule.rule_id for rule in rules}
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"custom rule #{index + 1} must be an object")
        required = ("id", "title", "severity", "pattern", "description", "recommendation")
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required):
            raise ValueError(f"custom rule #{index + 1} must define non-empty string fields: {', '.join(required)}")
        rule_id = item["id"].strip()
        if rule_id in existing:
            raise ValueError(f"duplicate rule id: {rule_id}")
        severity = item["severity"].lower().strip()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError(f"invalid severity for {rule_id}: {severity}")
        try:
            compiled = re.compile(item["pattern"], re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid regex for {rule_id}: {exc}") from exc
        rules.append(Rule(rule_id, item["title"].strip(), severity, compiled,
                          item["description"].strip(), item["recommendation"].strip()))
        existing.add(rule_id)
    return rules
