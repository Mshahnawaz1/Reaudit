"""Code-only verify gate: nothing unverified leaves this module."""
from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from .models import Area, Finding, Severity, Source

WINDOW = 3
MAX_READ_BYTES = 2_000_000


class Candidate(BaseModel):
    """A finding that has not passed the verify gate yet."""
    id: str
    area: Area
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    rule_ids: list[str] = Field(default_factory=list)
    source: Source
    title: str
    explanation: str
    suggested_fix: str
    file: str
    line: int
    end_line: int | None = None
    snippet: str
    cwe: str | None = None
    agent_note: str | None = None

    def to_finding(self) -> Finding:
        return Finding(**self.model_dump(), verified=True)


_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub("", s)


def _safe_path(root: Path, rel: str) -> Path | None:
    if not rel or "\x00" in rel or rel.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", rel):
        return None
    if ".." in Path(rel.replace("\\", "/")).parts:
        return None
    try:
        root_r = root.resolve()
        p = (root_r / rel).resolve()
        p.relative_to(root_r)
    except (ValueError, OSError):
        return None
    if not p.is_file():
        return None
    return p


def _read_lines(p: Path) -> list[str] | None:
    try:
        if p.stat().st_size > MAX_READ_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _locate(lines: list[str], line: int, snippet: str) -> int | None:
    """Return the 1-based line where the snippet starts, searching +-WINDOW lines, nearest first."""
    snip_lines = [s for s in snippet.splitlines() if s.strip()]
    if not snip_lines:
        return None
    want = _norm("".join(snip_lines))
    n = len(snip_lines)
    cands = sorted(range(line - WINDOW, line + WINDOW + 1), key=lambda x: (abs(x - line), x))
    for start in cands:
        if start < 1 or start > len(lines):
            continue
        for span in (n, n + 1):
            chunk = _norm("".join(lines[start - 1:start - 1 + span]))
            if want in chunk:
                return start
    # snippet may span the window as a whole (e.g. cited line is in the middle of it)
    lo, hi = max(1, line - WINDOW), min(len(lines), line + WINDOW)
    if want in _norm("".join(lines[lo - 1:hi])):
        return line
    return None


def verify_findings(candidates: list[Candidate], root: Path) -> tuple[list[Finding], int]:
    root = Path(root)
    cache: dict[str, list[str] | None] = {}
    verified: list[Finding] = []
    dropped = 0
    for c in candidates:
        try:
            if c.file not in cache:
                p = _safe_path(root, c.file)
                cache[c.file] = _read_lines(p) if p else None
            lines = cache[c.file]
            if lines is None or not (1 <= c.line <= max(len(lines), 1)) or c.line > len(lines):
                dropped += 1
                continue
            line = c.line
            if c.source != "rule":
                found = _locate(lines, c.line, c.snippet)
                if found is None:
                    dropped += 1
                    continue
                line = found
            end = c.end_line
            if end is not None:
                end = min(max(end, line), len(lines))
                end = None if end == line else end
            verified.append(c.model_copy(update={"line": line, "end_line": end}).to_finding())
        except Exception:
            dropped += 1
    return verified, dropped
