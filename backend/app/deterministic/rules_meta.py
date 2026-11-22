from __future__ import annotations

from dataclasses import dataclass

from .types import Area, Hit, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    area: Area
    severity: Severity
    cwe: str | None
    title: str
    fix_hint: str


_RULES = [
    Rule("SEC-001", "secrets", "critical", "CWE-798", "AWS access key ID committed", "Revoke the key in IAM, rotate, and load credentials from the environment or a secret manager."),
    Rule("SEC-002", "secrets", "critical", "CWE-798", "GitHub token committed", "Revoke the token in GitHub settings and use encrypted Actions secrets."),
    Rule("SEC-003", "secrets", "critical", "CWE-798", "Stripe live key committed", "Roll the key in the Stripe dashboard and load it from the environment."),
    Rule("SEC-004", "secrets", "high", "CWE-798", "Slack token or webhook committed", "Revoke the token/webhook in Slack and store it as a secret."),
    Rule("SEC-005", "secrets", "high", "CWE-798", "Google API key committed", "Restrict or delete the key in Google Cloud console and load it from the environment."),
    Rule("SEC-006", "secrets", "critical", "CWE-798", "Private key committed", "Remove the key from the repo and history, rotate it, and store it in a secret manager."),
    Rule("SEC-007", "secrets", "high", "CWE-798", "JSON Web Token committed", "Invalidate the token and never commit session or API tokens."),
    Rule("SEC-008", "secrets", "high", "CWE-798", "Hardcoded credential assignment", "Move the value to an environment variable or secret manager and rotate it."),
    Rule("SEC-009", "secrets", "medium", "CWE-798", "High-entropy string literal", "If this is a credential, move it to the environment and rotate it."),
    Rule("SEC-010", "secrets", "high", "CWE-540", "Sensitive file committed", "Remove the file from the repo and history, rotate its contents, and add it to .gitignore."),
    Rule("SEC-011", "secrets", "medium", "CWE-540", ".gitignore does not exclude .env files", "Add `.env` and `.env.*` (with `!.env.example`) to .gitignore."),
    Rule("SEC-012", "secrets", "critical", "CWE-798", "AWS secret access key committed", "Revoke the key in IAM, rotate, and load credentials from the environment."),
    Rule("DEP-001", "deps", "medium", None, "Dependency with known vulnerabilities", "Upgrade to a fixed version listed in the advisory."),
    Rule("DEP-002", "deps", "info", None, "Dependency version not pinned", "Pin an exact version (or commit a lockfile) so audits are reproducible."),
    Rule("CI-000", "ci", "info", None, "Unparseable workflow file", "Fix the YAML syntax so the workflow can be analyzed."),
    Rule("CI-001", "ci", "critical", "CWE-829", "pull_request_target checks out untrusted PR code", "Do not check out the PR head in a pull_request_target workflow; use pull_request, or split into an unprivileged build and a privileged workflow_run."),
    Rule("CI-002", "ci", "high", "CWE-94", "Untrusted GitHub context interpolated into script", "Pass the value via an `env:` variable and reference it as a shell variable instead of `${{ }}` inside run:."),
    Rule("CI-003", "ci", "medium", "CWE-829", "Action not pinned to a commit SHA", "Pin the action to a full 40-character commit SHA."),
    Rule("CI-004", "ci", "medium", "CWE-250", "Workflow lacks explicit permissions", "Add a top-level `permissions: contents: read` and grant extra scopes per job."),
    Rule("CI-005", "ci", "high", "CWE-250", "Overly broad workflow permissions", "Replace write-all with the minimal scopes each job needs."),
    Rule("CI-006", "ci", "high", "CWE-522", "Secrets exposed to fork-reachable trigger", "Do not use secrets in pull_request_target/workflow_run jobs that run untrusted code; gate with environments and approvals."),
    Rule("CI-007", "ci", "medium", "CWE-494", "Remote script piped to a shell", "Download, verify a checksum or signature, then execute; or use a pinned package."),
    Rule("CI-008", "ci", "high", "CWE-284", "Self-hosted runner reachable from pull requests", "Use GitHub-hosted runners for PR workflows or restrict who can trigger self-hosted runs."),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def make_hit(
    rule_id: str,
    file: str,
    line: int,
    snippet: str,
    explanation: str,
    *,
    severity: Severity | None = None,
    confidence: float = 0.9,
    end_line: int | None = None,
    title: str | None = None,
    cwe: str | None = None,
) -> Hit:
    r = RULES[rule_id]
    return Hit(
        rule_id=rule_id,
        area=r.area,
        severity=severity or r.severity,
        file=file,
        line=max(1, line),
        end_line=end_line,
        snippet=snippet.strip()[:300],
        cwe=cwe or r.cwe,
        title=title or r.title,
        explanation=explanation,
        confidence=confidence,
        fix_hint=r.fix_hint,
    )
