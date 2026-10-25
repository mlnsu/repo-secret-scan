"""Read-only scanner for likely credentials in a Git working tree."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    evidence: str


RULES = (
    Rule("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    Rule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    Rule("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    Rule("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Rule(
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|passwd|secret[_-]?key)\b\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9_./+=:@-]{8,})"
        ),
    ),
)

PLACEHOLDERS = {
    "changeme", "change-me", "replace-me", "your-token", "your_api_key",
    "example", "placeholder", "xxxxxxxx", "00000000", "null", "none",
}
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache",
}
MAX_FILE_SIZE = 1_000_000


def _git_files(root: Path) -> list[Path]:
    """Return tracked and non-ignored untracked files using Git's ignore rules."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    )
    return [root / os.fsdecode(item) for item in result.stdout.split(b"\0") if item]


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.strip().strip("'\"` ").lower()
    return normalized in PLACEHOLDERS or normalized.startswith(("your_", "your-", "<", "${"))


def _redact(line: str, start: int, end: int) -> str:
    """Keep surrounding context while never returning the matched credential."""
    return line[:start] + "[REDACTED]" + line[end:]


def scan_repository(path: str | Path) -> list[Finding]:
    """Scan one Git working tree. Findings never contain an unredacted match."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")

    try:
        files = _git_files(root)
    except FileNotFoundError as exc:
        raise RuntimeError("Git was not found. Install Git and try again.") from exc
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"Not a Git repository: {root}") from exc

    findings: list[Finding] = []
    for file_path in files:
        if any(part in SKIP_DIRS for part in file_path.relative_to(root).parts):
            continue
        try:
            # Do not follow repository symlinks out of the working tree.
            if file_path.is_symlink():
                continue
            if file_path.stat().st_size > MAX_FILE_SIZE:
                continue
            content = file_path.read_bytes()
            if b"\0" in content:
                continue
            text = content.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                match = rule.pattern.search(line)
                if not match:
                    continue
                secret = match.group(1) if rule.name == "credential-assignment" else match.group(0)
                if _looks_like_placeholder(secret):
                    continue
                findings.append(
                    Finding(
                        path=file_path.relative_to(root).as_posix(),
                        line=line_number,
                        rule=rule.name,
                        evidence="[REDACTED]",
                    )
                )
                break
    return findings
