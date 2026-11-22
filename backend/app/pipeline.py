"""Real-mode orchestration (implementation.md §2.3 event order).

Overridable hooks (tests inject fakes): AGENT_RUNNERS, INJECTION_SCAN, LEAD_FN. When None, the real
modules are imported lazily; a missing module degrades that stage instead of failing the job."""
from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from . import scoring
from .agents.lead import LeadOutput, apply_lead, code_rank, run_lead
from .agents.types import AgentResult, NewFinding
from .config import get_settings
from .dedupe import dedupe_findings
from .errors import AppError
from .ingest import CloneFn, RepoRef, ingest_repo
from .jobs import Job, now_iso
from .merge import merge_results
from .models import AuditReport, Finding, Hit, RepoInfo, RepoSnapshot, StageStatus
from .verify import verify_findings

log = logging.getLogger("repoguard")

TOTAL_TIMEOUT_S = 180
AGENT_TIMEOUT_S = 100
AGENT_NAMES = ("ci_agent", "code_agent", "secrets_agent")
_AGENT_MODULES = {
    "ci_agent": ("backend.app.agents.ci_agent", "run_ci_agent"),
    "code_agent": ("backend.app.agents.code_agent", "run_code_agent"),
    "secrets_agent": ("backend.app.agents.secrets_agent", "run_secrets_agent"),
}

AgentFn = Callable[[RepoSnapshot, list[Hit]], Awaitable[AgentResult]]
# test hooks
AGENT_RUNNERS: dict[str, AgentFn] | None = None
INJECTION_SCAN: Callable[[RepoSnapshot], Any] | None = None
LEAD_FN: Callable[[list[Finding], dict[str, Any]], Awaitable[LeadOutput]] | None = None


class NotImplementedPhase(Exception):
    pass


class AgentUnavailable(Exception):
    pass


def _resolve_agent(name: str) -> AgentFn:
    if AGENT_RUNNERS is not None and name in AGENT_RUNNERS:
        return AGENT_RUNNERS[name]
    mod, fn = _AGENT_MODULES[name]
    try:
        return getattr(importlib.import_module(mod), fn)
    except (ImportError, AttributeError) as e:
        raise AgentUnavailable(name) from e


_sems: dict[int, asyncio.Semaphore] = {}


def agent_semaphore() -> asyncio.Semaphore:
    loop_id = id(asyncio.get_running_loop())
    if loop_id not in _sems:
        _sems.clear()
        _sems[loop_id] = asyncio.Semaphore(get_settings().max_concurrent_agents)
    return _sems[loop_id]


class Stages:
    """Emits stage events and records status/duration for the report."""

    def __init__(self, job: Job):
        self.job = job
        self.status: dict[str, StageStatus] = {}
        self._t0: dict[str, float] = {}

    async def set(self, stage: str, state: str, message: str | None = None) -> None:
        now = time.monotonic()
        if state == "running":
            self._t0[stage] = now
        dur = int((now - self._t0[stage]) * 1000) if stage in self._t0 and state != "running" else None
        self.status[stage] = StageStatus(id=stage, state=state, message=message, duration_ms=dur)  # type: ignore[arg-type]
        await self.job.stage(stage, state, message)

    def ordered(self) -> list[StageStatus]:
        order = ["ingest", "deterministic", *AGENT_NAMES, "verify", "synthesize"]
        return [self.status.get(s) or StageStatus(id=s, state="skipped") for s in order]  # type: ignore[arg-type]


async def run_deterministic(snapshot: RepoSnapshot) -> tuple[list[Hit], list[Any]]:
    """Lazy bridge to deterministic.run_deterministic(root, files) -> (hits, warning codes)."""
    try:
        from .deterministic import run_deterministic as impl
    except ImportError:
        raise NotImplementedPhase("deterministic phase not available yet") from None
    raw_hits, warnings = await impl(snapshot.root, snapshot.files)
    hits = [Hit.model_validate(h.model_dump(exclude={"fix_hint"})) for h in raw_hits]
    return hits, warnings


def _warning_fields(w: Any) -> tuple[str, str]:
    if isinstance(w, str):
        return w, {"osv_unavailable": "OSV.dev unreachable; dependency CVE results are incomplete"}.get(w, w)
    if isinstance(w, dict):
        return str(w.get("code", "warning")), str(w.get("message", ""))
    if isinstance(w, (tuple, list)) and len(w) >= 2:
        return str(w[0]), str(w[1])
    return getattr(w, "code", "warning"), getattr(w, "message", str(w))


async def run_ingest_and_deterministic(
    job: Job, ref: RepoRef, clone_fn: CloneFn | None,
    after: Callable[[RepoSnapshot, list[Hit]], Awaitable[None]],
    stages: Stages | None = None,
) -> None:
    st = stages or Stages(job)
    await st.set("ingest", "running", "Cloning repository")
    t0 = time.monotonic()
    async with ingest_repo(ref, clone_fn) as snap:
        cov = snap.coverage
        await st.set("ingest", "done", f"{cov.files_scanned} files scanned, {cov.files_skipped} skipped")
        await st.set("deterministic", "running")
        try:
            hits, warnings = await run_deterministic(snap)
        except NotImplementedPhase as e:
            await job.warn("deterministic", "not_implemented", str(e))
            await st.set("deterministic", "skipped", str(e))
            hits, warnings = [], []
        else:
            for w in warnings:
                code, msg = _warning_fields(w)
                await job.warn("deterministic", code, msg)
            by_area: dict[str, int] = {"secrets": 0, "deps": 0, "ci": 0}
            for h in hits:
                by_area[h.area] = by_area.get(h.area, 0) + 1
            await job.emit("hits", {"stage": "deterministic", "by_area": by_area, "total": len(hits)})
            await st.set("deterministic", "degraded" if warnings else "done",
                         f"{len(hits)} candidate findings")
        await after(snap, hits)
    log.info("ingest+deterministic+rest finished in %.1fs", time.monotonic() - t0)


async def _run_one_agent(
    job: Job, st: Stages, name: str, snap: RepoSnapshot, hits: list[Hit]
) -> AgentResult | None:
    try:
        fn = _resolve_agent(name)
    except AgentUnavailable:
        await job.warn(name, "agent_unavailable", f"{name} is not available in this build")
        await st.set(name, "skipped", "Agent unavailable")
        return None
    try:
        async with agent_semaphore():
            await st.set(name, "running")
            await job.progress(name, f"{name} started")
            res = await asyncio.wait_for(fn(snap, hits), AGENT_TIMEOUT_S)
    except asyncio.TimeoutError:
        await job.warn(name, "agent_timeout", f"{name} timed out; continuing without it")
        await st.set(name, "degraded", "Timed out")
        return AgentResult(agent=name, status="degraded", warning="agent_timeout")  # type: ignore[arg-type]
    except Exception as e:
        log.warning("%s crashed: %s", name, type(e).__name__)
        await job.warn(name, "agent_failed", f"{name} failed ({type(e).__name__}); continuing without it")
        await st.set(name, "failed", "Agent crashed")
        return AgentResult(agent=name, status="failed", warning="agent_failed")  # type: ignore[arg-type]
    if not isinstance(res, AgentResult):
        await st.set(name, "failed", "Invalid agent output")
        return AgentResult(agent=name, status="failed", warning="agent_failed")  # type: ignore[arg-type]
    if res.warning:
        await job.warn(name, res.warning, res.notes or f"{name}: {res.warning}")
    msg = f"{len(res.verdicts)} verdicts, {len(res.new_findings)} new findings"
    await st.set(name, res.status if res.status != "ok" else "done", msg)
    return res


async def run_agents(job: Job, st: Stages, snap: RepoSnapshot, hits: list[Hit]) -> list[AgentResult]:
    results = await asyncio.gather(*(_run_one_agent(job, st, n, snap, hits) for n in AGENT_NAMES))
    return [r for r in results if r is not None]


async def _injection(job: Job, snap: RepoSnapshot) -> list[NewFinding]:
    fn = INJECTION_SCAN
    if fn is None:
        try:
            fn = importlib.import_module("backend.app.agents.injection_scan").scan_for_prompt_injection
        except (ImportError, AttributeError):
            return []
    try:
        res = fn(snap)
        if inspect.isawaitable(res):
            res = await res
        return list(res or [])
    except Exception as e:
        log.warning("injection scan failed: %s", type(e).__name__)
        await job.warn("verify", "injection_scan_failed", "Prompt-injection scan failed")
        return []


async def build_report(job: Job, st: Stages, snap: RepoSnapshot, ref: RepoRef, hits: list[Hit]) -> AuditReport:
    agent_results = await run_agents(job, st, snap, hits)
    if agent_results and all(r.status == "failed" for r in agent_results) and len(agent_results) == len(AGENT_NAMES):
        await job.warn("synthesize", "all_agents_failed", "All agents failed; showing deterministic findings only")
    elif not agent_results:
        await job.warn("synthesize", "agents_unavailable", "Agentic audit unavailable; showing deterministic findings only")
    injection = await _injection(job, snap)

    await st.set("verify", "running")
    candidates, dismissed = merge_results(hits, agent_results, injection)
    verified, dropped = verify_findings(candidates, snap.root)
    verified = dedupe_findings(verified)
    await st.set("verify", "done", f"{len(verified)} verified, {dropped} dropped as unverified")

    await st.set("synthesize", "running")
    meta = {"name": snap.name or ref.name, "languages": snap.coverage.languages}
    ranked = code_rank(verified)
    lead_fn = LEAD_FN or run_lead
    try:
        out = await lead_fn(ranked, meta)
    except Exception as e:
        log.warning("lead crashed: %s", type(e).__name__)
        from .agents.lead import fallback_output
        out = fallback_output(ranked, meta)
    if out.fallback:
        await job.warn("synthesize", "lead_fallback", "Lead synthesis unavailable; used code ranking")
    final = code_rank(apply_lead(ranked, out))
    ids = {f.id for f in final}
    top5 = [i for i in out.top5_ids if i in ids][:5] or [f.id for f in final[:5]]
    await st.set("synthesize", "degraded" if out.fallback else "done", f"score {scoring.score(final)}")

    return AuditReport(
        job_id=job.id,
        repo=RepoInfo(url=snap.url or ref.canonical_url, owner=snap.owner or ref.owner,
                      name=snap.name or ref.name, commit=snap.commit, branch=snap.branch),
        score=scoring.score(final), summary=out.summary, top5=top5, findings=final,
        dismissed=dismissed, dropped_unverified=dropped, coverage=snap.coverage,
        stages=st.ordered(), counts=scoring.counts(final),  # type: ignore[arg-type]
        generated_at=now_iso(),
    )


async def run_pipeline(job: Job, ref: RepoRef, clone_fn: CloneFn | None = None) -> None:
    st = Stages(job)

    async def later(snap: RepoSnapshot, hits: list[Hit]) -> None:
        job.report = await build_report(job, st, snap, ref, hits)
        await job.emit("done", {"job_id": job.id, "score": job.report.score})

    try:
        await asyncio.wait_for(run_ingest_and_deterministic(job, ref, clone_fn, later, st), TOTAL_TIMEOUT_S)
    except asyncio.TimeoutError:
        await job.fail("internal_error", "Audit exceeded the 180s time limit")
    except AppError as e:
        await job.fail(e.code, e.message)
    except Exception as e:  # never leak details
        log.exception("pipeline failed: %s", type(e).__name__)
        await job.fail("internal_error", "Internal error while auditing")
