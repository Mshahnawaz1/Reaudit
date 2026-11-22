from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from backend.app.agents import base
from backend.app.agents.prompts import SECRETS_SYSTEM, wrap_block
from backend.app.agents.tools import safe_read
from backend.app.agents.types import AgentResult, Sev, Verdict, hit_key
from backend.app.models import RepoSnapshot

CONTEXT = 8
MAX_HITS = 30


class SecretTriage(BaseModel):
    hit_key: str
    classification: Literal["real", "placeholder", "test_fixture", "docs_example"]
    decision: Literal["confirm", "dismiss", "adjust"]
    new_severity: Sev | None = None
    reason: str


class SecretsOutput(BaseModel):
    triage: list[SecretTriage] = []
    notes: str | None = None


def _context(snapshot: RepoSnapshot, file: str, line: int) -> str:
    text = safe_read(snapshot.root, file)
    if text is None:
        return "(file unreadable)"
    lines = text.splitlines()
    lo, hi = max(1, line - CONTEXT), min(len(lines), line + CONTEXT)
    return "\n".join(f"{i:>5}| {lines[i - 1]}" for i in range(lo, hi + 1))


async def run_secrets_agent(snapshot: RepoSnapshot, hits: list) -> AgentResult:
    sec = [h for h in hits if h.area == "secrets"]
    if not sec:
        return AgentResult(agent="secrets_agent", notes="No secret hits to triage.")
    batch, rest = sec[:MAX_HITS], sec[MAX_HITS:]
    items = [
        wrap_block(
            "ctx", _context(snapshot, h.file, h.line), hit_key=hit_key(h), rule=h.rule_id,
            file=h.file, line=str(h.line), severity=h.severity,
        )
        for h in batch
    ]
    prompt = (
        f"Triage these {len(batch)} suspected secrets. Each block shows the hit and its surrounding lines.\n\n"
        + "\n\n".join(items)
    )
    out = await base.run_structured(
        instructions=SECRETS_SYSTEM, prompt=prompt, output_model=SecretsOutput, timeout=45,
    )
    verdicts = [
        Verdict(hit_key=t.hit_key, decision=t.decision, new_severity=t.new_severity,
                reason=f"[{t.classification}] {t.reason}")
        for t in out.triage
    ]
    notes = out.notes
    if rest:
        notes = ((notes or "") + f" {len(rest)} hits beyond the {MAX_HITS}-hit batch cap were not reviewed.").strip()
    return AgentResult(agent="secrets_agent", verdicts=base.complete_verdicts(sec, verdicts), notes=notes)
