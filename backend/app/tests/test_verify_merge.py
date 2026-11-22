import os

from backend.app.agents.types import AgentResult, NewFinding, Verdict, hit_key
from backend.app.merge import finding_id, merge_results
from backend.app.models import Hit
from backend.app.verify import Candidate, verify_findings


def C(file="a.py", line=2, snippet="x = 1", source="agent", **kw):
    d = dict(id="i" + file + str(line), area="code", severity="high", confidence=0.9, rule_ids=[],
             source=source, title="t", explanation="e", suggested_fix="f", file=file, line=line, snippet=snippet)
    d.update(kw)
    return Candidate(**d)


def make_root(tmp_path):
    (tmp_path / "a.py").write_text("import os\nx   =  1\n\n\n\n\n\n\n\nsecret = 'abc'\n")
    return tmp_path


def test_verify_agent_ok_whitespace_normalized(tmp_path):
    v, d = verify_findings([C(snippet="x = 1")], make_root(tmp_path))
    assert len(v) == 1 and d == 0 and v[0].verified is True


def test_verify_autocorrects_line(tmp_path):
    v, d = verify_findings([C(line=4, snippet="x = 1")], make_root(tmp_path))
    assert v[0].line == 2


def test_verify_snippet_too_far_dropped(tmp_path):
    v, d = verify_findings([C(line=9, snippet="x = 1")], make_root(tmp_path))
    assert v == [] and d == 1


def test_verify_missing_file_and_out_of_range(tmp_path):
    root = make_root(tmp_path)
    v, d = verify_findings([C(file="nope.py"), C(line=999), C(line=0)], root)
    assert v == [] and d == 3


def test_verify_path_escape_and_symlink(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    (tmp_path / "outside.py").write_text("x = 1\n")
    os.symlink(tmp_path / "outside.py", root / "link.py")
    cs = [C(file="../outside.py", line=1), C(file="/etc/passwd", line=1), C(file="link.py", line=1)]
    v, d = verify_findings(cs, root)
    assert v == [] and d == 3


def test_verify_rule_hit_redacted_snippet_passes_but_range_checked(tmp_path):
    root = make_root(tmp_path)
    v, d = verify_findings([C(source="rule", line=10, snippet="secr…"), C(source="rule", line=50, snippet="x")], root)
    assert len(v) == 1 and d == 1


def test_verify_empty_snippet_agent_dropped(tmp_path):
    v, d = verify_findings([C(snippet="  ")], make_root(tmp_path))
    assert d == 1


def hit(**kw):
    d = dict(rule_id="CI-002", area="ci", severity="high", file="a.py", line=2, snippet="x", title="T",
             explanation="expl")
    d.update(kw)
    return Hit(**d)


def test_merge_verdicts():
    h1, h2, h3 = hit(), hit(rule_id="CI-003", line=3), hit(rule_id="CI-004", line=4)
    r = AgentResult(agent="ci_agent", verdicts=[
        Verdict(hit_key=hit_key(h1), decision="confirm", reason="real"),
        Verdict(hit_key=hit_key(h2), decision="dismiss", reason="fp"),
        Verdict(hit_key=hit_key(h3), decision="adjust", new_severity="low", reason="meh"),
    ])
    cands, dis = merge_results([h1, h2, h3], [r], [])
    assert [c.source for c in cands] == ["rule+agent", "rule+agent"]
    assert cands[0].agent_note == "real" and cands[1].severity == "low"
    assert len(dis) == 1 and dis[0].rule_id == "CI-003" and dis[0].reason == "fp"
    assert cands[0].suggested_fix  # from rules_meta fix_hint


def test_merge_uncovered_hit_labelled_when_agent_degraded_or_missing():
    h = hit()
    cands, _ = merge_results([h], [AgentResult(agent="ci_agent", status="degraded")], [])
    assert cands[0].source == "rule" and "Not agent-reviewed" in cands[0].agent_note
    cands, _ = merge_results([h], [], [])
    assert "Not agent-reviewed" in cands[0].agent_note
    cands, _ = merge_results([h], [AgentResult(agent="ci_agent")], [])
    assert cands[0].agent_note is None


def test_merge_new_and_injection_findings():
    nf = NewFinding(area="code", severity="high", confidence=0.7, title="SQLi", explanation="e",
                    suggested_fix="f", file="a.py", line=2, snippet="x = 1")
    inj = nf.model_copy(update={"title": "Injection attempt", "area": "code"})
    cands, _ = merge_results([], [AgentResult(agent="code_agent", new_findings=[nf])], [inj])
    assert cands[0].source == "agent" and cands[0].area == "code"
    assert cands[1].area == "meta"


def test_finding_id_stable():
    assert finding_id("a", 1, "R") == finding_id("a", 1, "R") != finding_id("a", 2, "R")
