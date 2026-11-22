"""Deterministic detector for prompt-injection attempts planted in repo text. No LLM."""
from __future__ import annotations

import re

from backend.app.agents.tools import safe_read
from backend.app.agents.types import NewFinding
from backend.app.models import RepoSnapshot

# (regex, severity)
PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.I), sev)
    for p, sev in [
        (r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules)", "medium"),
        (r"disregard\s+(all\s+|any\s+|the\s+)?(above|previous|prior|earlier|instructions?)", "medium"),
        (r"report\s+(a\s+)?score\s+(of\s+)?100", "medium"),
        (r"mark\s+(this|these|all|every)\b[^.\n]{0,40}\b(safe|secure|dismissed|false[- ]positives?)", "medium"),
        (r"(do\s+not|don't|never)\s+(report|flag)\s+(any|this|these)", "medium"),
        (r"dismiss\s+all\s+(findings|issues|hits)", "medium"),
        (r"new\s+instructions?\s*:", "medium"),
        (r"\byou\s+are\s+now\b", "low"),
        (r"\bsystem\s+prompt\b", "low"),
    ]
]
MAX_FINDINGS = 10


def scan_for_prompt_injection(snapshot: RepoSnapshot) -> list[NewFinding]:
    out: list[NewFinding] = []
    for f in snapshot.files:
        text = safe_read(snapshot.root, f.path)
        if not text:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for rx, sev in PATTERNS:
                if rx.search(line):
                    out.append(NewFinding(
                        area="meta", severity=sev, confidence=0.85 if sev == "medium" else 0.5,  # type: ignore[arg-type]
                        title="Possible prompt-injection attempt aimed at AI auditors",
                        explanation=(
                            "Repository text contains wording that addresses an AI/LLM reviewer and tries to "
                            "change its behaviour. RepoGuard treats repo content as data and did not obey it."
                        ),
                        suggested_fix="Remove this text from the repository; legitimate code and docs do not instruct automated reviewers.",
                        file=f.path, line=n, snippet=line.strip()[:300], cwe="CWE-1427",
                    ))
                    break
            if len(out) >= MAX_FINDINGS:
                return out
    return out
