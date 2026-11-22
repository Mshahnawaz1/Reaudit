"""Read-only, sandboxed repo tools for agents. No network, no writes, no shell."""
from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Callable, Iterable

from backend.app.agents.prompts import wrap_block, wrap_file
from backend.app.agents.types import hit_key

MAX_LINES = 300
MAX_MATCHES = 50
MAX_FILE_BYTES = 400_000
MAX_LISTING = 200
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


class SandboxError(Exception):
    pass


def resolve_in_root(root: Path, rel: str) -> Path:
    """Resolve `rel` under `root`; reject absolute paths, `..`, NULs and any symlink component."""
    if not isinstance(rel, str) or "\x00" in rel or len(rel) > 500:
        raise SandboxError("invalid path")
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel) or rel.startswith("~"):
        raise SandboxError("absolute paths are not allowed")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise SandboxError("'..' is not allowed")
    root_real = root.resolve()
    cur = root_real
    for p in parts:
        cur = cur / p
        if cur.is_symlink():
            raise SandboxError("symlinks are not allowed")
    resolved = cur.resolve()
    if resolved != root_real and root_real not in resolved.parents:
        raise SandboxError("path escapes repository")
    return resolved


class RepoTools:
    """Tool bundle bound to one clone root with a shared per-agent call budget."""

    def __init__(self, root: Path, hits: Iterable[object] = (), budget: int = 12) -> None:
        self.root = Path(root)
        self.hits = list(hits)
        self.budget = budget
        self.calls = 0

    def _spend(self) -> str | None:
        if self.calls >= self.budget:
            return f"tool budget exhausted ({self.budget} calls); answer with what you have"
        self.calls += 1
        return None

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.root.resolve()).as_posix()

    def list_dir(self, path: str = ".") -> str:
        """List files and directories in a repo directory (relative path, '.' for root)."""
        if (msg := self._spend()):
            return msg
        try:
            d = resolve_in_root(self.root, path)
            if not d.is_dir():
                return "error: not a directory"
            names = []
            for c in sorted(d.iterdir(), key=lambda x: x.name):
                if c.is_symlink() or c.name in SKIP_DIRS:
                    continue
                names.append(c.name + ("/" if c.is_dir() else ""))
            body = "\n".join(names[:MAX_LISTING]) or "(empty)"
            return wrap_block("tool", body, tool="list_dir", path=path)
        except SandboxError as e:
            return f"error: {e}"
        except OSError:
            return "error: cannot read directory"

    def read_file(self, path: str, start: int = 1, end: int = MAX_LINES) -> str:
        """Read a repo file with line numbers. start/end are 1-based inclusive; at most 300 lines per call."""
        if (msg := self._spend()):
            return msg
        try:
            f = resolve_in_root(self.root, path)
            if not f.is_file():
                return "error: not a file"
            if f.stat().st_size > MAX_FILE_BYTES:
                return "error: file too large"
            try:
                start, end = int(start), int(end)
            except (TypeError, ValueError):
                return "error: start/end must be integers"
            start = max(1, start)
            end = min(max(end, start), start + MAX_LINES - 1)
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            chunk = "\n".join(lines[start - 1 : end])
            return wrap_file(self._rel(f), chunk, start)
        except SandboxError as e:
            return f"error: {e}"
        except OSError:
            return "error: cannot read file"

    def grep(self, pattern: str, glob: str = "*") -> str:
        """Regex search across repo files (optional filename glob like '*.py'). Max 50 matches."""
        if (msg := self._spend()):
            return msg
        if not isinstance(pattern, str) or len(pattern) > 200:
            return "error: pattern too long"
        try:
            rx = re.compile(pattern)
        except re.error:
            return "error: invalid regex"
        root = self.root.resolve()
        out: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not Path(dirpath, d).is_symlink())
            for fn in sorted(filenames):
                p = Path(dirpath, fn)
                rel = p.relative_to(root).as_posix()
                if p.is_symlink() or not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(fn, glob)):
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if rx.search(line[:500]):
                        out.append(f"{rel}:{i}: {line[:300]}")
                        if len(out) >= MAX_MATCHES:
                            return wrap_block("tool", "\n".join(out) + "\n(truncated)", tool="grep")
        return wrap_block("tool", "\n".join(out) or "(no matches)", tool="grep")

    def get_deterministic_hits(self, area: str = "") -> str:
        """Return rule-based hits for an area (secrets, deps, ci, code, config) as hit_key | severity | file:line | title."""
        if (msg := self._spend()):
            return msg
        rows = [
            f"{hit_key(h)} | {h.severity} | {h.file}:{h.line} | {h.title}"
            for h in self.hits
            if not area or h.area == area
        ]
        return wrap_block("tool", "\n".join(rows[:MAX_MATCHES]) or "(none)", tool="get_deterministic_hits")

    def as_tools(self) -> list[Callable[..., str]]:
        return [self.list_dir, self.read_file, self.grep, self.get_deterministic_hits]


def safe_read(root: Path, rel: str, max_bytes: int = 200_000) -> str | None:
    """Sandboxed whole-file read for agent input building; None if unreadable/refused."""
    try:
        f = resolve_in_root(root, rel)
        if not f.is_file() or f.stat().st_size > max_bytes:
            return None
        return f.read_text(encoding="utf-8", errors="replace")
    except (SandboxError, OSError):
        return None
