import asyncio
import shutil
from pathlib import Path

import pytest

from backend.app import deterministic, pipeline
from backend.app.agents.lead import LeadOutput, fallback_output
from backend.app.agents.types import AgentResult, NewFinding, Verdict, hit_key
from backend.app.ingest import RepoRef
from backend.app.jobs import Job
from backend.app.models import AuditReport

SAMPLE = Path(__file__).parent / "fixtures" / "deterministic" / "sample_repo"
REF = RepoRef("octo", "sample")


async def fake_clone(ref, dest):
    shutil.copytree(SAMPLE, dest)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    async def no_osv(deps, client=None):
        return [], ["osv_unavailable"]
    monkeypatch.setattr(deterministic, "check_osv", no_osv)
    async def quiet(name):
        async def f(snap, hits):
            return AgentResult(agent=name)
        return f

    async def lead(findings, meta):
        return fallback_output(findings, meta)

    # never reach the real LLM from tests
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {n: asyncio.run(quiet(n)) for n in pipeline.AGENT_NAMES})
    monkeypatch.setattr(pipeline, "INJECTION_SCAN", lambda snap: [])
    monkeypatch.setattr(pipeline, "LEAD_FN", lead)


def nf(title="Hardcoded thing", line=3, snippet='password = "hunter2hunter2"'):
    return NewFinding(area="code", severity="high", confidence=0.8, title=title, explanation="e",
                      suggested_fix="f", file="app.py", line=line, snippet=snippet)


async def ok_ci(snap, hits):
    return AgentResult(agent="ci_agent", notes="fine")


async def ok_code(snap, hits):
    return AgentResult(agent="code_agent", new_findings=[nf(), nf("Fabricated", 3, "this text is not in the repo")])


async def crash_secrets(snap, hits):
    raise RuntimeError("boom AKIAIOSFODNN7EXAMPLE")


def run(clone=fake_clone):
    job = Job("j1", "https://github.com/octo/sample")
    asyncio.run(pipeline.run_pipeline(job, REF, clone))
    return job


def kinds(job):
    return [e for e, _ in job.events]


def test_end_to_end_with_degradation(monkeypatch):
    async def lead(findings, meta):
        return LeadOutput(summary="Sum.", top5_ids=[findings[0].id, "ghost"])
    inj = nf("Prompt injection attempt in README", 1, "import os")
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {"ci_agent": ok_ci, "code_agent": ok_code, "secrets_agent": crash_secrets})
    monkeypatch.setattr(pipeline, "INJECTION_SCAN", lambda snap: [inj])
    monkeypatch.setattr(pipeline, "LEAD_FN", lead)
    job = run()
    assert job.status == "done", job.error
    k = kinds(job)
    assert k[0] == "stage" and k[-1] == "done"
    assert k.index("hits") < [i for i, (e, d) in enumerate(job.events) if d.get("stage") == "ci_agent"][0]
    stage_seq = [(d["stage"], d["state"]) for e, d in job.events if e == "stage"]
    assert stage_seq[:3] == [("ingest", "running"), ("ingest", "done"), ("deterministic", "running")]
    assert ("secrets_agent", "failed") in stage_seq and ("ci_agent", "done") in stage_seq
    assert stage_seq.index(("verify", "running")) > stage_seq.index(("secrets_agent", "failed"))
    assert stage_seq[-1] == ("synthesize", "done")
    assert any(e == "warning" and d["code"] == "agent_failed" for e, d in job.events)
    assert any(e == "warning" and d["code"] == "osv_unavailable" for e, d in job.events)

    rep = AuditReport.model_validate(job.report.model_dump())
    assert rep.dropped_unverified >= 1
    assert all(f.verified for f in rep.findings)
    assert rep.findings and rep.summary == "Sum."
    assert any(f.area == "meta" for f in rep.findings)
    assert rep.top5 and "ghost" not in rep.top5
    assert [s.id for s in rep.stages][:2] == ["ingest", "deterministic"]
    assert next(s for s in rep.stages if s.id == "secrets_agent").state == "failed"
    assert next(s for s in rep.stages if s.id == "ingest").duration_ms is not None
    assert sum(rep.counts.values()) == len(rep.findings)
    assert 0 <= rep.score < 100
    assert not any("AKIA" in e.__repr__() and "crash" in e.__repr__() for e in job.events)


def test_verdict_dismiss_goes_to_dismissed(monkeypatch):
    async def secrets(snap, hits):
        h = next(h for h in hits if h.area == "secrets")
        return AgentResult(agent="secrets_agent", verdicts=[Verdict(hit_key=hit_key(h), decision="dismiss", reason="placeholder")])
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {"ci_agent": ok_ci, "code_agent": ok_code, "secrets_agent": secrets})
    job = run()
    assert job.report.dismissed and job.report.dismissed[0].reason == "placeholder"


def test_all_agents_fail_still_ships_deterministic(monkeypatch):
    async def bad(snap, hits):
        raise RuntimeError("x")
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {n: bad for n in pipeline.AGENT_NAMES})
    job = run()
    assert job.status == "done"
    assert job.report.findings
    assert all(f.source == "rule" for f in job.report.findings)
    assert all(s.state == "failed" for s in job.report.stages if s.id.endswith("_agent"))
    assert any(d.get("code") == "all_agents_failed" for e, d in job.events if e == "warning")
    assert job.report.summary


def test_agent_timeout_degrades(monkeypatch):
    async def slow(snap, hits):
        await asyncio.sleep(5)
    monkeypatch.setattr(pipeline, "AGENT_TIMEOUT_S", 0.05)
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {"ci_agent": slow, "code_agent": ok_code, "secrets_agent": ok_ci})
    job = run()
    assert job.status == "done"
    assert any(d.get("code") == "agent_timeout" for e, d in job.events if e == "warning")
    assert next(s for s in job.report.stages if s.id == "ci_agent").state == "degraded"


def test_agents_unavailable_degrades_not_fails(monkeypatch):
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {})
    monkeypatch.setattr(pipeline, "_AGENT_MODULES", {n: ("backend.app.agents.nonexistent_x", "f") for n in pipeline.AGENT_NAMES})
    job = run()
    assert job.status == "done" and job.report.findings


def test_lead_crash_falls_back(monkeypatch):
    async def lead(f, m):
        raise RuntimeError("x")
    monkeypatch.setattr(pipeline, "LEAD_FN", lead)
    job = run()
    assert job.status == "done" and len(job.report.top5) <= 5 and job.report.top5


def test_concurrency_capped_at_two(monkeypatch):
    active = 0
    peak = 0

    def mk(name):
        async def f(snap, hits):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1
            return AgentResult(agent=name)
        return f
    monkeypatch.setattr(pipeline, "AGENT_RUNNERS", {n: mk(n) for n in pipeline.AGENT_NAMES})
    run()
    assert peak == 2


def test_ingest_failure_emits_error_and_cleans(monkeypatch):
    from backend.app.errors import make_error

    async def nf_clone(ref, dest):
        raise make_error("repo_not_found", "nope")
    job = run(nf_clone)
    assert job.status == "failed" and job.error[0] == "repo_not_found"
    assert "done" not in kinds(job)
