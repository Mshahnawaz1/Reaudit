from __future__ import annotations

from .models import Finding

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _span(f: Finding) -> tuple[int, int]:
    return f.line, max(f.line, f.end_line or f.line)


def _related(a: Finding, b: Finding) -> bool:
    if a.file != b.file:
        return False
    (s1, e1), (s2, e2) = _span(a), _span(b)
    if s2 > e1 + 1 or s1 > e2 + 1:
        return False
    # same rule on different lines = distinct occurrences
    if a.rule_ids and a.rule_ids == b.rule_ids and a.line != b.line:
        return False
    return a.area == b.area or (a.cwe is not None and a.cwe == b.cwe)


def _merge(a: Finding, b: Finding) -> Finding:
    win, other = sorted((a, b), key=lambda f: (SEV_RANK[f.severity], -f.confidence, -len(f.explanation)))
    sources = {a.source, b.source}
    source = win.source if len(sources) == 1 else "rule+agent"
    explanation = max((a.explanation, b.explanation), key=len) if not win.explanation else win.explanation
    if len(other.explanation) > len(win.explanation) * 2:
        explanation = other.explanation
    s = min(win.line, other.line)
    e = max(_span(win)[1], _span(other)[1])
    return win.model_copy(update={
        "rule_ids": list(dict.fromkeys([*win.rule_ids, *other.rule_ids])),
        "source": source,
        "explanation": explanation,
        "suggested_fix": win.suggested_fix or other.suggested_fix,
        "cwe": win.cwe or other.cwe,
        "agent_note": win.agent_note or other.agent_note,
        "confidence": max(win.confidence, other.confidence),
        "line": win.line if win.line == s else s,
        "end_line": e if e > s else None,
        "snippet": win.snippet if win.line == s else other.snippet,
    })


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for f in sorted(findings, key=lambda x: (x.file, x.line)):
        for i, g in enumerate(out):
            if _related(g, f):
                out[i] = _merge(g, f)
                break
        else:
            out.append(f)
    return out
