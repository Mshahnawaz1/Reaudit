import asyncio

import pytest

from backend.app.agents import base, ci_agent, code_agent, secrets_agent
from backend.app.agents.base import AgentError, AgentOutput, run_agent_safely, run_structured
from backend.app.agents.secrets_agent import SecretsOutput, SecretTriage
from backend.app.agents.types import AgentResult, Verdict, hit_key
from backend.app.ingest import build_snapshot
from backend.app.models import Hit


def mkhit(rule, area, f, line, sev="high"):
    return Hit(rule_id=rule, area=area, severity=sev, file=f, line=line, snippet="s", title="t")


@pytest.fixture
def snap(tmp_path):
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/workflows/ci.yml").write_text("on: pull_request_target\njobs: {}\n")
    (tmp_path / "Dockerfile").write_text("FROM x\nRUN curl http://a | sh\n")
    (tmp_path / "server.py").write_text("import os\nos.system(request.args['c'])\n")
    (tmp_path / "config.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "util.py").write_text("x = 1\n")
    return build_snapshot(tmp_path)


def fake(monkeypatch, result, seen=None):
    async def _f(**kw):
        if seen is not None:
            seen.append(kw)
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(base, "run_structured", _f)


def test_ci_defaults_missing_verdicts_to_confirm(snap, monkeypatch):
    hits = [mkhit("CI-001", "ci", ".github/workflows/ci.yml", 1), mkhit("CI-002", "ci", ".github/workflows/ci.yml", 2)]
    v = Verdict(hit_key=hit_key(hits[0]), decision="dismiss", reason="r")
    junk = Verdict(hit_key="nope:x:1", decision="dismiss", reason="r")
    seen = []
    fake(monkeypatch, AgentOutput(verdicts=[v, junk]), seen)
    res = asyncio.run(ci_agent.run_ci_agent(snap, hits + [mkhit("SEC-1", "secrets", "a", 1)]))
    assert res.status == "ok" and [x.decision for x in res.verdicts] == ["dismiss", "confirm"]
    assert res.verdicts[1].reason == "not reviewed by agent"
    p = seen[0]["prompt"]
    assert "<repo_file path=\".github/workflows/ci.yml\">" in p and "Dockerfile" in p and "SEC-1" not in p
    assert seen[0]["tools"]


def test_ci_skips_without_llm(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x=1\n")
    fake(monkeypatch, RuntimeError("must not be called"))
    res = asyncio.run(ci_agent.run_ci_agent(build_snapshot(tmp_path), []))
    assert res.status == "ok" and res.notes and not res.verdicts


def test_secrets_batch_one_call_and_prefix(snap, monkeypatch):
    hits = [mkhit("SEC-001", "secrets", "config.py", 1), mkhit("SEC-002", "secrets", "config.py", 1)]
    seen = []
    t = SecretTriage(hit_key=hit_key(hits[0]), classification="placeholder", decision="dismiss", reason="AWS docs key")
    fake(monkeypatch, SecretsOutput(triage=[t]), seen)
    res = asyncio.run(secrets_agent.run_secrets_agent(snap, hits))
    assert len(seen) == 1 and "AKIAIOSFODNN7EXAMPLE" in seen[0]["prompt"]
    assert res.verdicts[0].reason.startswith("[placeholder]") and res.verdicts[0].decision == "dismiss"
    assert res.verdicts[1].decision == "confirm"


def test_secrets_skip_when_no_hits(snap, monkeypatch):
    fake(monkeypatch, RuntimeError("no"))
    assert asyncio.run(secrets_agent.run_secrets_agent(snap, [])).status == "ok"


def test_code_ranking_and_skip(snap, tmp_path, monkeypatch):
    ranked = code_agent.rank_files(snap)
    paths = [p for _, p, _ in ranked]
    assert paths[0] == "server.py" and "util.py" not in paths
    seen = []
    fake(monkeypatch, AgentOutput(), seen)
    res = asyncio.run(code_agent.run_code_agent(snap, []))
    assert res.status == "ok" and "server.py" in seen[0]["prompt"]
    empty = tmp_path / "e"
    empty.mkdir()
    (empty / "x.py").write_text("y=1\n")
    fake(monkeypatch, RuntimeError("no"))
    assert asyncio.run(code_agent.run_code_agent(build_snapshot(empty), [])).notes


@pytest.mark.parametrize("code,status", [("agent_timeout", "degraded"), ("schema_invalid", "degraded"), ("llm_unavailable", "failed")])
def test_degradation(snap, monkeypatch, code, status):
    fake(monkeypatch, AgentError(code))
    res = asyncio.run(run_agent_safely("ci_agent", lambda: ci_agent.run_ci_agent(snap, [mkhit("CI-001", "ci", "x", 1)])))
    assert (res.status, res.warning, res.agent) == (status, code, "ci_agent")


def test_unexpected_exception_is_failed():
    async def boom():
        raise ValueError("x")
    res = asyncio.run(run_agent_safely("code_agent", boom))
    assert res.status == "failed" and res.warning == "internal_error"


def test_fail_llm_env(monkeypatch):
    monkeypatch.setenv("FAIL_LLM", "1")
    with pytest.raises(AgentError) as e:
        asyncio.run(run_structured(instructions="i", prompt="p", output_model=AgentOutput))
    assert e.value.code == "llm_unavailable"


def _patch_invoke(monkeypatch, behaviors):
    calls = []
    async def _inv(**kw):
        calls.append(kw["prompt"])
        b = behaviors[min(len(calls) - 1, len(behaviors) - 1)]
        if isinstance(b, Exception):
            raise b
        return b
    monkeypatch.setattr(base, "_invoke", _inv)
    monkeypatch.setattr(base, "_BACKOFF_BASE", 0.0)
    monkeypatch.setenv("GEMINI_API_KEY", "k-test")
    return calls


def run(**kw):
    return asyncio.run(run_structured(instructions="i", prompt="p", output_model=AgentOutput, **kw))


def test_timeout_retries_then_agent_timeout(monkeypatch):
    calls = _patch_invoke(monkeypatch, [asyncio.TimeoutError()])
    with pytest.raises(AgentError) as e:
        run()
    assert e.value.code == "agent_timeout" and len(calls) == 2


def test_schema_repair_retry_succeeds(monkeypatch):
    calls = _patch_invoke(monkeypatch, ["not json", '{"notes": "ok"}'])
    assert run().notes == "ok" and "did not match" in calls[1]


def test_schema_invalid_after_retry(monkeypatch):
    _patch_invoke(monkeypatch, ["bad", '{"verdicts": 5}'])
    with pytest.raises(AgentError) as e:
        run()
    assert e.value.code == "schema_invalid"


def test_429_backoff_then_success(monkeypatch):
    calls = _patch_invoke(monkeypatch, [RuntimeError("429 RESOURCE_EXHAUSTED"), RuntimeError("429"), AgentOutput(notes="n")])
    assert run().notes == "n" and len(calls) == 3


def test_429_exhausted(monkeypatch):
    _patch_invoke(monkeypatch, [RuntimeError("429")])
    with pytest.raises(AgentError) as e:
        run()
    assert e.value.code == "llm_unavailable"


def test_semaphore_limits_concurrency(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_AGENTS", "2")
    active = peak = 0
    async def _inv(**kw):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return AgentOutput()
    monkeypatch.setattr(base, "_invoke", _inv)
    monkeypatch.setenv("GEMINI_API_KEY", "k-test")
    async def go():
        await asyncio.gather(*[run_structured(instructions="i", prompt="p", output_model=AgentOutput) for _ in range(6)])
    asyncio.run(go())
    assert peak == 2
