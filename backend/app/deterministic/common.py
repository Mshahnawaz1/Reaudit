from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MAX_READ = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".idea"}
MAX_WALK_FILES = 5000


@dataclass
class FileRef:
    path: str
    size: int
    lang: str | None = None
    area: str | None = None
    abs_path: Path | None = None


def walk(root: Path) -> list[FileRef]:
    out: list[FileRef] = []
    stack = [root]
    while stack and len(out) < MAX_WALK_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in SKIP_DIRS:
                    stack.append(p)
            elif p.is_file():
                out.append(FileRef(p.relative_to(root).as_posix(), p.stat().st_size, None, None, p))
    return out


def normalize(root: Path, files: Iterable[object]) -> list[FileRef]:
    refs: list[FileRef] = []
    for f in files:
        rel = str(getattr(f, "path")).replace("\\", "/").lstrip("/")
        ap = getattr(f, "abs_path", None)
        refs.append(
            FileRef(
                rel,
                int(getattr(f, "size", 0) or 0),
                getattr(f, "lang", None),
                getattr(f, "area", None),
                Path(ap) if ap else root / rel,
            )
        )
    return refs


def read_text(f: FileRef) -> str | None:
    p = f.abs_path
    if p is None or p.is_symlink():
        return None
    try:
        if p.stat().st_size > MAX_READ:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]
