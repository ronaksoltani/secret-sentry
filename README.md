# Secret Sentry

> A small, explainable CLI that catches common secrets before they reach Git history.

Secret Sentry scans text files for recognizable credential formats and risky assignments. It prints file, line, rule, and severity, while redacting the matching value by default. It never uploads scanned content and never edits or deletes files.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate | macOS/Linux: source .venv/bin/activate
python -m pip install -e .
secret-sentry scan .
```

Example output:

```text
src/settings.py:12: HIGH github-token — possible GitHub access token [redacted]
Scan complete: 1 finding(s), 42 file(s) checked, 3 skipped.
```

Use `--json report.json` to save machine-readable findings, `--ignore .secretignore` to load path globs, or `--show-values` only in a private local terminal. Add `# secret-scan: ignore` to a line only when the match is a known false positive.

## What it detects

The built-in rules cover private-key headers, common GitHub/AWS/Slack token shapes, and credential-like assignments such as `api_key = "..."`. Pattern scanning is a useful guardrail, not proof that a repository is secret-free. Add organization-specific patterns and review every finding.

## Layout

- `src/secret_sentry/scanner.py`: file walking, rule matching, and redaction.
- `src/secret_sentry/cli.py`: command-line interface and exit codes.
- `tests/`: focused examples of the public scanning behavior.

## Learning notes

The scanner combines `pathlib` for safe path handling, compiled regular expressions for recognizable formats, and dataclasses for structured findings. The CLI returns exit code `1` when it finds a match, making it usable in a pre-commit hook or CI job.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
```

## Safety

This is not a replacement for a dedicated secret-management or secret-scanning service. Rotate a credential immediately if it was committed, even if the commit was later removed.

## License

MIT. See [LICENSE](LICENSE).
