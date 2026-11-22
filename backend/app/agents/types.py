"""Shared interface between specialist agents (B3) and the pipeline/synthesis (B4)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from backend.app.models import Hit

Sev = Literal["critical", "high", "medium", "low", "info"]
Area = Literal["secrets", "deps", "ci", "code", "config", "meta"]


def hit_key(hit: Hit) -> str:
    """Stable id an agent uses to refer to a deterministic hit."""
    return f"{hit.rule_id}:{hit.file}:{hit.line}"


class Verdict(BaseModel):
    hit_key: str
    decision: Literal["confirm", "dismiss", "adjust"]
    new_severity: Sev | None = None
    reason: str


class NewFinding(BaseModel):
    area: Area
    severity: Sev
    confidence: float = Field(ge=0, le=1)
    title: str
    explanation: str
    suggested_fix: str
    file: str
    line: int
    end_line: int | None = None
    snippet: str  # exact repo text; verified later by verify.py
    cwe: str | None = None


class AgentResult(BaseModel):
    agent: Literal["ci_agent", "code_agent", "secrets_agent"]
    status: Literal["ok", "degraded", "failed"] = "ok"
    verdicts: list[Verdict] = []
    new_findings: list[NewFinding] = []
    notes: str | None = None
    warning: str | None = None  # e.g. "agent_timeout", "llm_unavailable"
