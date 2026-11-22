from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Area = Literal["secrets", "deps", "ci", "code", "config", "meta"]
StageId = Literal[
    "ingest", "deterministic", "ci_agent", "code_agent", "secrets_agent", "verify", "synthesize"
]
StageState = Literal["pending", "running", "done", "degraded", "failed", "skipped"]
ErrorCode = Literal[
    "invalid_url", "unsupported_host", "repo_not_found", "repo_private_or_forbidden",
    "repo_empty", "repo_too_large", "clone_timeout", "job_not_found",
    "job_not_ready", "rate_limited", "llm_unavailable", "internal_error",
]
Source = Literal["rule", "agent", "rule+agent"]

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


class Finding(BaseModel):
    id: str
    area: Area
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    rule_ids: list[str]
    source: Source
    title: str
    explanation: str
    suggested_fix: str
    file: str
    line: int = Field(ge=1)
    end_line: int | None = None
    snippet: str
    cwe: str | None = None
    agent_note: str | None = None
    verified: Literal[True] = True


class DismissedHit(BaseModel):
    rule_id: str
    file: str
    line: int
    reason: str


class StageStatus(BaseModel):
    id: StageId
    state: StageState
    message: str | None = None
    duration_ms: int | None = None


class Coverage(BaseModel):
    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    skipped_reasons: dict[str, int] = Field(default_factory=dict)
    languages: list[str] = Field(default_factory=list)
    reduced_coverage_languages: list[str] = Field(default_factory=list)
    caps_hit: list[str] = Field(default_factory=list)


class RepoInfo(BaseModel):
    url: str
    owner: str
    name: str
    commit: str
    branch: str


class AuditReport(BaseModel):
    job_id: str
    repo: RepoInfo
    score: int = Field(ge=0, le=100)
    summary: str
    top5: list[str]
    findings: list[Finding]
    dismissed: list[DismissedHit]
    dropped_unverified: int
    coverage: Coverage
    stages: list[StageStatus]
    counts: dict[Severity, int]
    generated_at: str


class IssueDraft(BaseModel):
    finding_id: str
    title: str
    labels: list[str]
    body_markdown: str


class ApiErrorBody(BaseModel):
    code: ErrorCode
    message: str
    detail: str | None = None


class ApiError(BaseModel):
    error: ApiErrorBody


class AuditRequest(BaseModel):
    repo_url: str


class AuditAccepted(BaseModel):
    job_id: str


class IssueDraftsRequest(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=10)


class IssueDraftsResponse(BaseModel):
    drafts: list[IssueDraft]


class Health(BaseModel):
    status: Literal["ok"] = "ok"
    mock: bool
    model: str


# ---- internal (not part of the HTTP contract) ----

class Hit(BaseModel):
    rule_id: str
    area: Area
    severity: Severity
    file: str
    line: int
    end_line: int | None = None
    snippet: str
    cwe: str | None = None
    title: str
    explanation: str | None = None
    confidence: float = 0.9


class FileEntry(BaseModel):
    path: str  # repo-relative, forward slashes
    size: int
    lang: Literal["py", "js", "ts", "other"]
    area: Literal["ci", "app_code", "manifest", "env", "docker", "other"]


class RepoSnapshot(BaseModel):
    root: Path
    commit: str
    branch: str
    owner: str = ""
    name: str = ""
    url: str = ""
    files: list[FileEntry]
    coverage: Coverage
