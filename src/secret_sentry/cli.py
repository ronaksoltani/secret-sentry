from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import scan_path


def _read_ignore_file(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secret-sentry", description="Scan files locally for common secrets.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", type=Path, nargs="?", default=Path("."))
    scan.add_argument("--ignore", type=Path, default=Path(".secretignore"), help="newline-separated glob rules")
    scan.add_argument("--json", type=Path, dest="json_path", help="write a JSON report")
    scan.add_argument("--show-values", action="store_true", help="show matched text (avoid in shared terminals)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings, checked, skipped = scan_path(args.path,
            ignore_patterns=_read_ignore_file(args.ignore), show_values=args.show_values)
    except (OSError, ValueError) as error:
        print(f"error: {error}")
        return 2
    for item in findings:
        print(f"{item.path}:{item.line}: {item.severity.upper()} {item.rule} — {item.redacted}")
    print(f"Scan complete: {len(findings)} finding(s), {checked} file(s) checked, {skipped} skipped.")
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2) + "\n", encoding="utf-8")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
