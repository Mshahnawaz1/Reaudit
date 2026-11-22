from backend.app.dedupe import dedupe_findings
from backend.app.models import Finding
from backend.app.scoring import counts, score


def F(sev="low", file="a.py", line=1, area="code", rules=None, cwe=None, source="rule", expl="e", end=None, fid=None):
    return Finding(id=fid or f"{file}{line}{sev}{area}", area=area, severity=sev, confidence=0.8,
                   rule_ids=rules or [], source=source, title="t", explanation=expl, suggested_fix="f",
                   file=file, line=line, end_line=end, snippet="s", cwe=cwe)


def test_score_empty_and_info():
    assert score([]) == 100
    assert score([F("info") for _ in range(20)]) == 100


def test_score_weights_and_caps():
    assert score([F("critical")]) == 75
    assert score([F("critical", line=i) for i in range(1, 4)]) == 25  # cap 75
    assert score([F("critical", line=i) for i in range(1, 10)]) == 25
    assert score([F("high", line=i) for i in range(1, 20)]) == 52
    assert score([F("medium", line=i) for i in range(1, 20)]) == 75
    assert score([F("low", line=i) for i in range(1, 20)]) == 90


def test_score_floor_zero_possible_range():
    fs = [F(s, line=i) for s in ("critical", "high", "medium", "low") for i in range(1, 30)]
    assert score(fs) == 100 - 75 - 48 - 25 - 10 or score(fs) == 0
    assert score(fs) == 0


def test_counts_all_keys():
    c = counts([F("high"), F("high", line=2), F("info", line=3)])
    assert c == {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 1}


def test_dedupe_overlap_same_area_keeps_max_severity_and_unions_rules():
    a = F("medium", line=5, area="ci", rules=["CI-004"], cwe="CWE-250", expl="short")
    b = F("high", line=6, area="ci", rules=["CI-005"], cwe="CWE-250", expl="a much longer explanation here")
    out = dedupe_findings([a, b])
    assert len(out) == 1
    assert out[0].severity == "high"
    assert set(out[0].rule_ids) == {"CI-004", "CI-005"}
    assert out[0].line == 5 and out[0].end_line == 6


def test_dedupe_same_rule_different_lines_kept():
    a = F(line=5, area="ci", rules=["CI-003"])
    b = F(line=6, area="ci", rules=["CI-003"])
    assert len(dedupe_findings([a, b])) == 2


def test_dedupe_different_file_or_far_lines_kept():
    assert len(dedupe_findings([F(line=1, file="a"), F(line=1, file="b")])) == 2
    assert len(dedupe_findings([F(line=1), F(line=10)])) == 2


def test_dedupe_different_area_no_cwe_kept_same_cwe_merged():
    assert len(dedupe_findings([F(line=1, area="ci"), F(line=1, area="code")])) == 2
    assert len(dedupe_findings([F(line=1, area="ci", cwe="CWE-1"), F(line=1, area="code", cwe="CWE-1")])) == 1


def test_dedupe_source_union():
    out = dedupe_findings([F("high", rules=["R"], source="rule"), F("medium", source="agent", area="code")])
    assert out[0].source == "rule+agent"
