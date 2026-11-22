from __future__ import annotations

from pathlib import Path
from typing import Iterable

import httpx

from .ci_rules import scan_ci
from .common import normalize, walk
from .deps import check_osv, collect_deps, unpinned_hits
from .secrets import scan_secrets
from .types import SEVERITY_ORDER, Hit, ScanFile

__all__ = ["run_deterministic", "Hit", "ScanFile"]


async def run_deterministic(
    root: Path,
    files: Iterable[object] | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> tuple[list[Hit], list[str]]:
    """Run all deterministic rules. Returns (hits, warning_codes). No LLM, never raises on OSV failure."""
    root = Path(root)
    refs = walk(root) if files is None else normalize(root, files)
    warnings: list[str] = []
    hits: list[Hit] = []
    hits += scan_secrets(refs)
    hits += scan_ci(refs)
    deps = collect_deps(refs)
    hits += unpinned_hits(deps)
    osv_hits, osv_warn = await check_osv(deps, http_client)
    hits += osv_hits
    warnings += osv_warn
    hits.sort(key=lambda h: (SEVERITY_ORDER[h.severity], h.file, h.line, h.rule_id))
    return hits, warnings
