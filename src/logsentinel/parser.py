"""Best-effort parser for plain text, common syslog, and JSON Lines logs."""
from __future__ import annotations
import json
import re
from collections.abc import Iterable, Iterator
from .models import LogEvent

_SYSLOG = re.compile(
    r"^(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[\w./@-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_ISO_PREFIX = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\S+)\s+(?P<message>.*)$")


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def parse_lines(lines: Iterable[str]) -> Iterator[LogEvent]:
    """Parse lines without modifying the input; malformed JSON falls back to text."""
    for number, source in enumerate(lines, start=1):
        raw = source.rstrip("\r\n")
        if not raw.strip():
            continue
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                item = json.loads(stripped)
                if isinstance(item, dict):
                    msg = next((item[k] for k in ("message", "msg", "log", "event") if isinstance(item.get(k), str)), None)
                    if msg is not None:
                        pid = item.get("pid")
                        try:
                            pid = int(pid) if pid is not None else None
                        except (TypeError, ValueError):
                            pid = None
                        yield LogEvent(
                            line_number=number, raw=raw, message=msg,
                            timestamp=_string(item.get("timestamp") or item.get("time") or item.get("@timestamp")),
                            host=_string(item.get("host") or item.get("hostname")),
                            service=_string(item.get("service") or item.get("program") or item.get("process")),
                            pid=pid, level=_string(item.get("level") or item.get("severity")),
                            source_format="json",
                        )
                        continue
            except (json.JSONDecodeError, TypeError):
                pass
        match = _SYSLOG.match(stripped)
        if match:
            groups = match.groupdict()
            yield LogEvent(line_number=number, raw=raw, message=groups["message"],
                           timestamp=groups["timestamp"], host=groups["host"],
                           service=groups["service"], pid=int(groups["pid"]) if groups["pid"] else None,
                           source_format="syslog")
            continue
        iso = _ISO_PREFIX.match(stripped)
        if iso:
            yield LogEvent(line_number=number, raw=raw, message=iso.group("message"),
                           timestamp=iso.group("timestamp"), source_format="timestamped")
            continue
        yield LogEvent(line_number=number, raw=raw, message=raw, source_format="plain")
