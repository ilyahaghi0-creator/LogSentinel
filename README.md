# LogSentinel

**A small, read-only, rule-based log analyzer for Linux and application logs.** LogSentinel scans a supplied file (or standard input), parses common line formats, checks configurable regular-expression rules, and produces a text or JSON report. It uses only the Python standard library at runtime and never connects to the network.

> **Scope:** this is an educational starter project, not a SIEM or a production intrusion-detection system. A match is an indicator for human review, not proof of compromise. No match does not prove that a system is safe. Built-in rules are deliberately simple and do not perform cross-line correlation or rate calculations.

## Features

- Parses plain text, common RFC 3164-style syslog lines, timestamp-prefixed lines, and JSON Lines with common message fields.
- Includes starter rules for authentication failures, repeated-authentication wording, privilege-related activity, service failures, and possible security-control changes.
- Adds custom regex rules from a JSON file without editing the Python package.
- Emits readable text or machine-readable JSON reports with line numbers and review recommendations.
- Reads input files without changing them; no network calls and no third-party runtime dependencies.
- Unit tests use Python's built-in `unittest` framework.

## Requirements

- Python 3.10 or newer.

## Quick start (Kali Linux / Linux)

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
logsentinel examples/sample.log
logsentinel examples/sample.log --format json
logsentinel examples/sample.log --rules examples/custom_rules.json
```

Without installing the package, run it from the project root with:

```bash
PYTHONPATH=src python -m logsentinel.cli examples/sample.log
```

Read from standard input:

```bash
cat examples/sample.log | logsentinel - --format json
```

## Custom rules

The rules file must contain a JSON array. Each rule needs six non-empty string fields: `id`, `title`, `severity`, `pattern`, `description`, and `recommendation`. Allowed severities: `critical`, `high`, `medium`, `low`, `info`. Regexes are case-insensitive. Rule IDs must not duplicate built-in or other custom IDs. Invalid files and regexes produce a clear error and exit code 2.

Example:

```json
[
  {
    "id": "CUSTOM-001",
    "title": "Example marker",
    "severity": "info",
    "pattern": "\\bEXAMPLE_MARKER\\b",
    "description": "An example marker appeared.",
    "recommendation": "Review the event in context."
  }
]
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Exit behavior

- `0`: analysis completed (whether or not findings were reported).
- `2`: invalid arguments, input/rule file error, or invalid custom rule configuration.

## Project layout

```text
src/logsentinel/   parser, rules, analyzer, reporting, CLI
 tests/            unit tests
 examples/         sample log and custom rules
```

## Security and limitations

- Treat log files as sensitive: reports may repeat log content and identifiers.
- Regex rules can produce false positives and false negatives; validate them on representative logs before operational use.
- The tool reads a full input into memory in this initial version, so avoid feeding it very large files until streaming support is implemented.
- JSON parsing recognizes common fields but is not a universal schema mapper.
- The “repeated authentication” rule identifies wording in a single line; it does not infer repeated attempts across lines.
- Test only on logs you are authorized to access.

## Roadmap

- Streaming analysis for large files.
- Optional cross-line/time-window correlation with explicit tests.
- More format fixtures and adversarial parser tests.
- Baseline and regression tests against a curated, privacy-safe sample corpus.

## License

MIT. See [LICENSE](LICENSE).
