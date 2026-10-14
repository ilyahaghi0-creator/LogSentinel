"""Command-line interface."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from . import __version__
from .analyzer import analyze
from .parser import parse_lines
from .reporter import to_json, to_text
from .rules import load_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logsentinel", description="Read-only, rule-based log analyzer.")
    parser.add_argument("input", nargs="?", help="log file to analyze; omit or use - for standard input")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="report format (default: text)")
    parser.add_argument("--rules", metavar="FILE", help="JSON file containing additional detection rules")
    parser.add_argument("--version", action="version", version=f"LogSentinel {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source = args.input or "-"
    try:
        rules = load_rules(args.rules)
        if source == "-":
            events = list(parse_lines(sys.stdin))
            source_label = "stdin"
        else:
            path = Path(source)
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                events = list(parse_lines(handle))
            source_label = str(path)
        findings = analyze(events, rules)
        report = to_json(findings, source=source_label) if args.format == "json" else to_text(findings, source=source_label)
        sys.stdout.write(report)
        return 0
    except (OSError, ValueError) as exc:
        print(f"logsentinel: error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
