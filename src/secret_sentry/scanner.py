"""Fast, local scanning for common credential patterns."""

from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    redacted: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


RULES = (
    Rule("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    Rule("github-token", "high", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    Rule("aws-access-key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Rule("slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    Rule("credential-assignment", "medium", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token)\b"
        r"\s*[:=]\s*(['\"])(?!\s*(?:$|your[_ -]|example|changeme|redacted))[^'\"\r\n]{8,}\1"
    )),
)

DEFAULT_IGNORES = (".git/**", ".venv/**", "venv/**", "__pycache__/**", "node_modules/**")
MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_ignored(relative: str, patterns: Iterable[str]) -> bool:
    normalized = relative.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch("/" + normalized, pattern)
               for pattern in patterns)


def _entropy(value: str) -> float:
    """Shannon entropy; exposed for learners extending the rules."""
    if not value:
        return 0.0
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in
                 (value.count(char) for char in set(value)) if n)


def scan_text(text: str, path: str = "<memory>", *, show_values: bool = False) -> list[Finding]:
    """Return one finding per matching rule and line, redacting by default."""
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "secret-scan: ignore" in line:
            continue
        for rule in RULES:
            match = rule.pattern.search(line)
            if match:
                # Never put a captured value in the default report.
                value = match.group(0) if show_values else "[redacted]"
                findings.append(Finding(path, line_number, rule.name, rule.severity, value))
    return findings


def scan_path(root: Path, *, ignore_patterns: Iterable[str] = (), show_values: bool = False
              ) -> tuple[list[Finding], int, int]:
    """Scan a file or directory; return findings, files checked, files skipped."""
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    patterns = (*DEFAULT_IGNORES, *ignore_patterns)
    findings: list[Finding] = []
    checked = skipped = 0
    for file_path in files:
        relative = file_path.name if root.is_file() else file_path.relative_to(root).as_posix()
        if _is_ignored(relative, patterns):
            skipped += 1
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
            raw = file_path.read_bytes()
        except OSError:
            skipped += 1
            continue
        if b"\0" in raw[:8192]:
            skipped += 1
            continue
        checked += 1
        findings.extend(scan_text(raw.decode("utf-8", errors="replace"), relative,
                                  show_values=show_values))
    return findings, checked, skipped
