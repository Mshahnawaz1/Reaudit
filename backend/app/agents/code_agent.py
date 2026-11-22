from __future__ import annotations

import re

from backend.app.agents import base
from backend.app.agents.prompts import CODE_SYSTEM, wrap_file, wrap_hits
from backend.app.agents.tools import RepoTools, safe_read
from backend.app.agents.types import AgentResult, hit_key
from backend.app.models import RepoSnapshot

TOP_FILES = 20
BYTE_BUDGET = 80_000
MAX_LINES_PER_FILE = 400
PATH_RX = re.compile(r"(route|api|view|auth|login|controller|handler|db|query|server|app)", re.I)
SINK_RX = re.compile(
    r"\b(exec|eval|execSync|spawn|subprocess|os\.system|pickle|yaml\.load|marshal|innerHTML|"
    r"dangerouslySetInnerHTML|child_process|render_template_string)\b|"
    r"(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(\+|%s|%\(|f\"|f'|\$\{|\.format\()|debug\s*=\s*True|origins?\s*[:=]\s*[\"']\*",
    re.I,
)
TEST_RX = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|node_modules)/|\.(test|spec)\.", re.I)


def rank_files(snapshot: RepoSnapshot) -> list[tuple[int, str, str]]:
    """Deterministic ranking: (score, path, text), best first, only files with score > 0."""
    ranked: list[tuple[int, str, str]] = []
    for f in snapshot.files:
        if f.lang not in ("py", "js", "ts") or f.area == "ci":
            continue
        text = safe_read(snapshot.root, f.path)
        if text is None:
            continue
        sinks = len(SINK_RX.findall(text))
        score = (2 if PATH_RX.search(f.path) else 0) + 3 * min(sinks, 5)
        if TEST_RX.search(f.path):
            score //= 3
        if score > 0:
            ranked.append((score, f.path, text))
    ranked.sort(key=lambda r: (-r[0], r[1]))
    return ranked


async def run_code_agent(snapshot: RepoSnapshot, hits: list) -> AgentResult:
    code_hits = [h for h in hits if h.area in ("code", "config")]
    ranked = rank_files(snapshot)
    if not ranked and not code_hits:
        return AgentResult(agent="code_agent", notes="No Python/JS/TS files with security-relevant routes or sinks.")

    blocks: list[str] = []
    used = 0
    for _, path, text in ranked[:TOP_FILES]:
        text = "\n".join(text.splitlines()[:MAX_LINES_PER_FILE])
        if used + len(text) > BYTE_BUDGET:
            continue
        used += len(text)
        blocks.append(wrap_file(path, text))

    prompt = (
        "Review the application code below for vulnerabilities.\n\nIncoming rule hits (one verdict required for each; "
        "empty list means none):\n" + wrap_hits(code_hits, hit_key)
        + "\n\nFiles (ranked by risk):\n" + ("\n\n".join(blocks) or "(none)")
        + "\n\nReturn verdicts and any additional findings."
    )
    tools = RepoTools(snapshot.root, hits)
    out = await base.run_structured(
        instructions=CODE_SYSTEM, prompt=prompt, output_model=base.AgentOutput, tools=tools.as_tools(), timeout=45,
    )
    return AgentResult(
        agent="code_agent", verdicts=base.complete_verdicts(code_hits, out.verdicts),
        new_findings=out.new_findings, notes=out.notes,
    )
