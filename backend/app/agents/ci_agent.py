from __future__ import annotations

from backend.app.agents import base
from backend.app.agents.prompts import CI_SYSTEM, wrap_file, wrap_hits
from backend.app.agents.tools import RepoTools, safe_read
from backend.app.agents.types import AgentResult, hit_key
from backend.app.models import RepoSnapshot

BYTE_BUDGET = 60_000
MAX_DOCKER_LINES = 150


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") or path.startswith(".github/actions/") or path.endswith((".gitlab-ci.yml",))


async def run_ci_agent(snapshot: RepoSnapshot, hits: list) -> AgentResult:
    ci_hits = [h for h in hits if h.area == "ci"]
    wf = [f for f in snapshot.files if f.area == "ci" or _is_workflow(f.path)]
    docker = [f for f in snapshot.files if f.area == "docker" and "dockerfile" in f.path.lower()]
    if not ci_hits and not wf and not docker:
        return AgentResult(agent="ci_agent", notes="No CI workflows, Dockerfiles or CI hits to review.")

    blocks: list[str] = []
    used = 0
    for f in wf + docker:
        text = safe_read(snapshot.root, f.path)
        if text is None:
            continue
        if f in docker:
            text = "\n".join(text.splitlines()[:MAX_DOCKER_LINES])
        if used + len(text) > BYTE_BUDGET:
            break
        used += len(text)
        blocks.append(wrap_file(f.path, text))

    prompt = (
        "Review the CI/CD configuration below.\n\nIncoming rule hits (one verdict required for each):\n"
        + wrap_hits(ci_hits, hit_key)
        + "\n\nFiles:\n" + ("\n\n".join(blocks) or "(none readable)")
        + "\n\nReturn verdicts for every hit and any additional findings."
    )
    tools = RepoTools(snapshot.root, hits)
    out = await base.run_structured(
        instructions=CI_SYSTEM, prompt=prompt, output_model=base.AgentOutput, tools=tools.as_tools(), timeout=45,
    )
    return AgentResult(
        agent="ci_agent", verdicts=base.complete_verdicts(ci_hits, out.verdicts),
        new_findings=out.new_findings, notes=out.notes,
    )
