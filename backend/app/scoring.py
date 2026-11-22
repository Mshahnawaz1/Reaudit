from __future__ import annotations

from collections.abc import Iterable

from .models import SEVERITIES, Finding

# severity -> (weight per finding, max total deduction)
WEIGHTS: dict[str, tuple[int, int]] = {
    "critical": (25, 75),
    "high": (12, 48),
    "medium": (5, 25),
    "low": (2, 10),
    "info": (0, 0),
}


def counts(findings: Iterable[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        out[f.severity] += 1
    return out


def score(findings: Iterable[Finding]) -> int:
    c = counts(findings)
    total = sum(min(w * c[sev], cap) for sev, (w, cap) in WEIGHTS.items())
    return max(0, min(100, 100 - total))
