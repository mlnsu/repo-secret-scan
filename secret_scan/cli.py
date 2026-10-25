"""Command-line entry point."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .scanner import scan_repository


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secret-scan",
        description="Scan a local Git working tree for likely secrets (values are redacted).",
    )
    parser.add_argument(
        "paths", nargs="*", help="one or more Git repository paths (default: current directory)"
    )
    args = parser.parse_args()
    paths = args.paths or ["."]
    total_findings = 0
    had_error = False

    for path in paths:
        try:
            findings = scan_repository(Path(path))
        except (RuntimeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            had_error = True
            continue

        total_findings += len(findings)
        print(f"{Path(path)}:")
        if not findings:
            print("  No likely secrets found.")
            continue
        for finding in findings:
            print(f"  {finding.path}:{finding.line} [{finding.rule}] {finding.evidence}")

    if total_findings:
        print(f"Found {total_findings} likely secret(s). Review matches; false positives are possible.")
    return 2 if had_error else (1 if total_findings else 0)


if __name__ == "__main__":
    raise SystemExit(main())
