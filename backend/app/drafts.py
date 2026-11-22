from __future__ import annotations

from .errors import make_error
from .models import AuditReport, Finding, IssueDraft

BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def permalink(report: AuditReport, f: Finding) -> str:
    r = report.repo
    frag = f"#L{f.line}" + (f"-L{f.end_line}" if f.end_line and f.end_line > f.line else "")
    return f"https://github.com/{r.owner}/{r.name}/blob/{r.commit}/{f.file}{frag}"


def build_draft(report: AuditReport, f: Finding) -> IssueDraft:
    rules = ", ".join(f.rule_ids) if f.rule_ids else "agent-detected"
    lines = [
        f"**Severity:** `{BADGE[f.severity]}`  ·  **Area:** {f.area}  ·  **Rule:** {rules}"
        + (f"  ·  **{f.cwe}**" if f.cwe else ""),
        "",
        f"**Location:** [{f.file}:{f.line}]({permalink(report, f)})",
        "",
        "### What is wrong",
        f.explanation,
        "",
        "### Evidence",
        "```",
        f.snippet,
        "```",
        "",
        "### Suggested fix",
        f.suggested_fix,
        "",
        "---",
        f"_Drafted by RepoGuard from commit `{report.repo.commit[:7]}` (dry run, not filed automatically)._",
    ]
    return IssueDraft(
        finding_id=f.id,
        title=f"[{BADGE[f.severity]}] {f.title}",
        labels=["security", f"severity:{f.severity}", f"repoguard:{f.area}"],
        body_markdown="\n".join(lines),
    )


def build_drafts(report: AuditReport, finding_ids: list[str]) -> list[IssueDraft]:
    by_id = {f.id: f for f in report.findings}
    unknown = [i for i in finding_ids if i not in by_id]
    if unknown:
        e = make_error("internal_error", f"Unknown finding ids: {', '.join(unknown[:5])}")
        e.status = 400
        raise e
    return [build_draft(report, by_id[i]) for i in dict.fromkeys(finding_ids)]
