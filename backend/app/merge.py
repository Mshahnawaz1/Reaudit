"""Apply agent verdicts to deterministic hits and collect agent findings as unverified candidates."""
from __future__ import annotations

import hashlib

from .agents.types import AgentResult, NewFinding, hit_key
from .models import DismissedHit, Hit
from .verify import Candidate

AREA_AGENT = {"ci": "ci_agent", "secrets": "secrets_agent", "code": "code_agent"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def finding_id(file: str, line: int, rule_or_title: str) -> str:
    return hashlib.sha1(f"{file}:{line}:{rule_or_title}".encode()).hexdigest()[:10]


def _fix_hint(rule_id: str) -> str:
    try:
        from .deterministic.rules_meta import RULES
        return RULES[rule_id].fix_hint if rule_id in RULES else ""
    except ImportError:
        return ""


def _unique(c: Candidate, seen: set[str]) -> Candidate:
    base, n = c.id, 1
    while c.id in seen:
        n += 1
        c = c.model_copy(update={"id": finding_id(c.file, c.line, f"{base}{n}")})
    seen.add(c.id)
    return c


def merge_results(
    hits: list[Hit],
    agent_results: list[AgentResult],
    injection_findings: list[NewFinding] | None = None,
) -> tuple[list[Candidate], list[DismissedHit]]:
    verdicts = {}
    reviewed_ok: set[str] = set()
    for r in agent_results:
        if r.status == "failed":
            continue
        if r.status == "ok":
            reviewed_ok.add(r.agent)
        for v in r.verdicts:
            verdicts.setdefault(v.hit_key, v)

    candidates: list[Candidate] = []
    dismissed: list[DismissedHit] = []
    seen: set[str] = set()

    for h in hits:
        v = verdicts.get(hit_key(h))
        severity, source, note = h.severity, "rule", None
        if v is not None:
            if v.decision == "dismiss":
                dismissed.append(DismissedHit(rule_id=h.rule_id, file=h.file, line=h.line, reason=v.reason))
                continue
            source, note = "rule+agent", v.reason
            if v.decision == "adjust" and v.new_severity:
                severity = v.new_severity
        else:
            agent = AREA_AGENT.get(h.area)
            if agent and agent not in reviewed_ok:
                note = f"Not agent-reviewed ({agent} unavailable or degraded); deterministic rule match only."
        candidates.append(_unique(Candidate(
            id=finding_id(h.file, h.line, h.rule_id), area=h.area, severity=severity,
            confidence=h.confidence, rule_ids=[h.rule_id], source=source, title=h.title,
            explanation=h.explanation or h.title, suggested_fix=_fix_hint(h.rule_id),
            file=h.file, line=h.line, end_line=h.end_line, snippet=h.snippet, cwe=h.cwe, agent_note=note,
        ), seen))

    def from_new(n: NewFinding, area: str | None = None) -> Candidate:
        return Candidate(
            id=finding_id(n.file, n.line, n.title), area=area or n.area, severity=n.severity,
            confidence=n.confidence, rule_ids=[], source="agent", title=n.title,
            explanation=n.explanation, suggested_fix=n.suggested_fix, file=n.file, line=n.line,
            end_line=n.end_line, snippet=n.snippet, cwe=n.cwe,
        )

    for r in agent_results:
        if r.status == "failed":
            continue
        for n in r.new_findings:
            candidates.append(_unique(from_new(n), seen))
    for n in injection_findings or []:
        candidates.append(_unique(from_new(n, "meta"), seen))
    return candidates, dismissed
