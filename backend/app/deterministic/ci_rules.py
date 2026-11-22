from __future__ import annotations

import re
from typing import Iterator

import yaml

from .common import FileRef, read_text
from .rules_meta import make_hit
from .types import Hit

WF_PATH = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
PRIVILEGED = {"pull_request_target", "workflow_run", "issue_comment", "issues", "pull_request_review", "pull_request_review_comment", "discussion", "discussion_comment"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
UNTRUSTED = re.compile(
    r"\$\{\{[^}]*?(github\.head_ref|github\.event\.(?!repository)[\w.\[\]*-]*?"
    r"(?:title|body|\bref|label|message|name|email|head_branch|page_name|default_branch|display_title))[^}]*\}\}"
)
HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.|github\.head_ref|github\.event\.workflow_run\.head_|refs/pull/")
PIPE_SHELL = re.compile(r"(?:\b(?:curl|wget)\b[^|\n;&]*\|\s*(?:sudo\s+(?:-\S+\s+)?)?(?:ba|z|da|k)?sh\b)|(?:\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b)")
SECRET_REF = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)\w+")
WRITE_SCOPES_BROAD = 3


def mget(node: yaml.Node | None, key: str) -> tuple[yaml.Node, yaml.Node] | None:
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode) and k.value == key:
                return k, v
    return None


def scalar(node: yaml.Node | None) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def items(node: yaml.Node | None) -> Iterator[tuple[str, yaml.Node]]:
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode):
                yield k.value, v


def triggers(root: yaml.Node) -> set[str]:
    m = mget(root, "on") or mget(root, "true")
    if not m:
        return set()
    v = m[1]
    if isinstance(v, yaml.ScalarNode):
        return {v.value}
    if isinstance(v, yaml.SequenceNode):
        return {s.value for s in v.value if isinstance(s, yaml.ScalarNode)}
    return {k for k, _ in items(v)}


def walk_scalars(node: yaml.Node) -> Iterator[yaml.ScalarNode]:
    if isinstance(node, yaml.ScalarNode):
        yield node
    elif isinstance(node, yaml.SequenceNode):
        for c in node.value:
            yield from walk_scalars(c)
    elif isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            yield from walk_scalars(v)


class Ctx:
    def __init__(self, path: str, lines: list[str]):
        self.path, self.lines = path, lines

    def locate(self, node: yaml.Node, needle: str | None = None) -> tuple[int, str]:
        start = node.start_mark.line
        if needle:
            first = needle.strip().splitlines()[0].strip() if needle.strip() else ""
            end = max(node.end_mark.line + 1, start + 1)
            for i in range(start, min(end + 1, len(self.lines))):
                if first and first in self.lines[i]:
                    return i + 1, self.lines[i].strip()
        return start + 1, (self.lines[start].strip() if start < len(self.lines) else "")


def _steps(job: yaml.Node) -> list[yaml.Node]:
    m = mget(job, "steps")
    return [s for s in m[1].value if isinstance(s, yaml.MappingNode)] if m and isinstance(m[1], yaml.SequenceNode) else []


def analyze_workflow(path: str, text: str) -> list[Hit]:
    lines = text.splitlines()
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as e:
        ln = getattr(getattr(e, "problem_mark", None), "line", 0) + 1
        return [make_hit("CI-000", path, ln, lines[ln - 1] if ln <= len(lines) else "", "The workflow could not be parsed as YAML, so no CI rules were applied to it.", confidence=0.9)]
    if not isinstance(root, yaml.MappingNode):
        return []
    ctx = Ctx(path, lines)
    trig = triggers(root)
    priv = bool(trig & PRIVILEGED)
    jobs_m = mget(root, "jobs")
    jobs = list(items(jobs_m[1])) if jobs_m else []
    hits: list[Hit] = []

    top_perm = mget(root, "permissions")
    hits += _permissions(ctx, root, top_perm, jobs, jobs_m, trig)
    for jname, job in jobs:
        hits += _job_rules(ctx, jname, job, trig, priv)
    if "pull_request_target" in trig or "workflow_run" in trig:
        hits += _secrets_exposed(ctx, jobs, trig)
    return hits


def _permissions(ctx, root, top_perm, jobs, jobs_m, trig) -> list[Hit]:
    hits: list[Hit] = []
    scopes: list[tuple[str, yaml.Node | None, yaml.Node]] = []
    if top_perm:
        scopes.append(("workflow", top_perm[0], top_perm[1]))
    for jname, job in jobs:
        jp = mget(job, "permissions")
        if jp:
            scopes.append((f"job `{jname}`", jp[0], jp[1]))
    for where, knode, vnode in scopes:
        val = scalar(vnode)
        ln, snip = ctx.locate(knode)
        if val == "write-all":
            hits.append(make_hit("CI-005", ctx.path, ln, snip, f"The {where} grants `write-all`, giving the GITHUB_TOKEN write access to every scope."))
        elif isinstance(vnode, yaml.MappingNode) and where == "workflow":
            writes = [k for k, v in items(vnode) if scalar(v) == "write"]
            if len(writes) >= WRITE_SCOPES_BROAD:
                hits.append(make_hit("CI-005", ctx.path, ln, snip, f"The workflow-level permissions grant write on {len(writes)} scopes ({', '.join(writes)}) to every job.", severity="medium"))
    if not top_perm:
        missing = [(n, j) for n, j in jobs if not mget(j, "permissions")]
        if missing and jobs_m:
            n, j = missing[0]
            priv = bool(trig & {"pull_request_target", "workflow_run"})
            ln, snip = ctx.locate(_job_key(jobs_m[1], n))
            names = ", ".join(f"`{m[0]}`" for m in missing[:5])
            hits.append(make_hit("CI-004", ctx.path, ln, snip, f"No top-level `permissions:` and job(s) {names} set none, so the GITHUB_TOKEN gets the repository default (often read/write).", severity="medium" if priv else "low"))
    return hits


def _job_key(jobs_node: yaml.Node, name: str) -> yaml.Node:
    for k, _ in jobs_node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == name:
            return k
    return jobs_node


def _job_rules(ctx: Ctx, jname: str, job: yaml.Node, trig: set[str], priv: bool) -> list[Hit]:
    hits: list[Hit] = []
    pr_trig = bool(trig & {"pull_request", "pull_request_target"})
    ro = mget(job, "runs-on")
    if ro and pr_trig:
        labels = [s.value for s in walk_scalars(ro[1])]
        if any("self-hosted" in lbl for lbl in labels):
            ln, snip = ctx.locate(ro[1], "self-hosted")
            hits.append(make_hit("CI-008", ctx.path, ln, snip, f"Job `{jname}` runs on a self-hosted runner and the workflow triggers on pull requests, so PR authors may run code on your infrastructure."))
    for step in _steps(job):
        uses = mget(step, "uses")
        if uses and scalar(uses[1]):
            hits += _uses_rules(ctx, scalar(uses[1]) or "", uses[1], step, trig)
        run = mget(step, "run")
        if run and scalar(run[1]):
            hits += _run_rules(ctx, scalar(run[1]) or "", run[1], priv)
        if uses and "github-script" in (scalar(uses[1]) or ""):
            w = mget(step, "with")
            sc = mget(w[1], "script") if w else None
            if sc and scalar(sc[1]):
                hits += _run_rules(ctx, scalar(sc[1]) or "", sc[1], priv, injection_only=True)
    return hits


def _uses_rules(ctx: Ctx, uses: str, node: yaml.Node, step: yaml.Node, trig: set[str]) -> list[Hit]:
    hits: list[Hit] = []
    if uses.startswith(("./", "docker://")):
        return hits
    action, _, ref = uses.partition("@")
    if not SHA40.match(ref):
        official = action.split("/")[0] in ("actions", "github")
        branch = ref in ("main", "master", "HEAD", "") 
        sev = "low" if official else ("high" if branch else "medium")
        ln, snip = ctx.locate(node, uses)
        hits.append(make_hit("CI-003", ctx.path, ln, snip, f"`{uses}` is referenced by {'branch' if branch else 'mutable tag'} `{ref or '(none)'}`, not a 40-character commit SHA, so the code behind it can change.", severity=sev, confidence=0.8 if official else 0.9))
    if "pull_request_target" in trig and action.lower() == "actions/checkout":
        w = mget(step, "with")
        for key in ("ref", "repository"):
            m = mget(w[1], key) if w else None
            if m and scalar(m[1]) and HEAD_REF.search(scalar(m[1]) or ""):
                ln, snip = ctx.locate(m[1], scalar(m[1]))
                hits.append(make_hit("CI-001", ctx.path, ln, snip, "A pull_request_target workflow (which has secrets and a write token) checks out code from the pull request head, letting a fork run arbitrary code with those privileges."))
    return hits


def _run_rules(ctx: Ctx, run: str, node: yaml.Node, priv: bool, injection_only: bool = False) -> list[Hit]:
    hits: list[Hit] = []
    for m in UNTRUSTED.finditer(run):
        ln, snip = ctx.locate(node, m.group(0))
        hits.append(make_hit("CI-002", ctx.path, ln, snip, f"`{m.group(0)}` is attacker-controllable and is expanded into the script before the shell runs, allowing command injection.", severity="high" if priv else "medium"))
    if not injection_only:
        for m in PIPE_SHELL.finditer(run):
            ln, snip = ctx.locate(node, m.group(0)[:40])
            hits.append(make_hit("CI-007", ctx.path, ln, snip, "A remote script is downloaded and piped straight into a shell without verification."))
    return hits


def _secrets_exposed(ctx: Ctx, jobs: list[tuple[str, yaml.Node]], trig: set[str]) -> list[Hit]:
    hits: list[Hit] = []
    which = "pull_request_target" if "pull_request_target" in trig else "workflow_run"
    for jname, job in jobs:
        checks_head = any(
            (u := mget(s, "uses")) and "checkout" in (scalar(u[1]) or "") and (w := mget(s, "with")) and any(HEAD_REF.search(x.value) for x in walk_scalars(w[1]))
            for s in _steps(job)
        )
        for sc in walk_scalars(job):
            m = SECRET_REF.search(sc.value)
            if m:
                ln, snip = ctx.locate(sc, m.group(0))
                hits.append(make_hit("CI-006", ctx.path, ln, snip, f"Job `{jname}` uses a repository secret in a `{which}` workflow, which fork pull requests can trigger." + (" The job also checks out PR head code." if checks_head else ""), severity="high" if checks_head else "medium", confidence=0.85 if checks_head else 0.6))
    return hits[:10]


def scan_ci(files: list[FileRef]) -> list[Hit]:
    hits: list[Hit] = []
    for f in files:
        if WF_PATH.match(f.path):
            text = read_text(f)
            if text is not None:
                hits.extend(analyze_workflow(f.path, text))
    return hits
