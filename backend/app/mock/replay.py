from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

from ..jobs import Job, now_iso
from ..models import AuditReport
from ..ingest import RepoRef

HERE = Path(__file__).parent
MOCK_URL_RE = re.compile(r"^(?P<base>https://github\.com/[^/\s]+/[^/\s]+)/mock/(?P<kind>not-found|degraded|slow)/?$")


def split_mock_url(url: str) -> tuple[str, str | None]:
    """'https://github.com/o/r/mock/slow' -> ('https://github.com/o/r', 'slow')."""
    m = MOCK_URL_RE.match((url or "").strip())
    return (m["base"], m["kind"]) if m else (url, None)


def _load(name: str):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def build_report(job_id: str, ref: RepoRef, kind: str | None) -> AuditReport:
    data = _load("report.json")
    data["job_id"] = job_id
    data["repo"].update(url=ref.canonical_url, owner=ref.owner, name=ref.name)
    data["generated_at"] = now_iso()
    if kind == "degraded":
        for s in data["stages"]:
            if s["id"] == "code_agent":
                s.update(state="degraded", message="Timed out after 60s; partial results")
            if s["id"] == "deterministic":
                s.update(state="degraded", message="OSV unavailable; dependency results incomplete")
    return AuditReport.model_validate(data)


async def run_mock(job: Job, ref: RepoRef, kind: str | None) -> None:
    scale = float(os.environ.get("MOCK_DELAY_SCALE", "1"))
    if kind == "slow":
        scale *= 4
    events = _load("events.json")
    if kind == "not-found":
        seq = events["not_found"]
    else:
        variant = "degraded" if kind == "degraded" else "default"
        seq = [e for e in events["audit"] if e.get("variant", variant) == variant]
    report = build_report(job.id, ref, kind)
    job.report = report
    for e in seq:
        await asyncio.sleep(e["delay_ms"] / 1000 * scale)
        data = dict(e["data"])
        if e["event"] == "done":
            data = {"job_id": job.id, "score": report.score}
        await job.emit(e["event"], data)
