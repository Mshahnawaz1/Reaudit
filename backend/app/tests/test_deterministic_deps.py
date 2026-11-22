import asyncio
import json
from pathlib import Path

import httpx

from backend.app.deterministic import run_deterministic
from backend.app.deterministic.deps import (
    check_osv,
    parse_package_json,
    parse_package_lock,
    parse_pyproject,
    parse_requirements,
    vuln_severity,
)


def handler_ok(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/querybatch":
        qs = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-xxxx-0001"}]} if q["package"]["name"] == "flask" else {} for q in qs]})
    if request.url.path == "/v1/vulns/GHSA-xxxx-0001":
        return httpx.Response(200, json={
            "id": "GHSA-xxxx-0001", "summary": "Bad thing",
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}],
        })
    return httpx.Response(404)


def run_with(tmp_path: Path, files: dict[str, str], handler):
    for n, c in files.items():
        (tmp_path / n).write_text(c)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return asyncio.run(run_deterministic(tmp_path, http_client=client))


def test_requirements_parser():
    deps = parse_requirements("requirements.txt", "# c\nflask==0.12\nrequests>=2.0\nDjango[x]~=4.2 ; python_version>'3'\n-r other.txt\nnumpy\n")
    got = {(d.name, d.version, d.line) for d in deps}
    assert ("flask", "0.12", 2) in got and ("requests", None, 3) in got and ("django", None, 4) in got and ("numpy", None, 6) in got
    assert len(deps) == 4


def test_pyproject_parser():
    text = '[project]\nname="a"\ndependencies = [\n  "flask==0.12",\n  "httpx>=0.2",\n]\n[project.optional-dependencies]\ndev = ["pytest==8.0.0"]\n[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "2.0.0"\n'
    got = {(d.name, d.version, d.line) for d in parse_pyproject("pyproject.toml", text)}
    assert ("flask", "0.12", 4) in got and ("httpx", None, 5) in got and ("pytest", "8.0.0", 8) in got and ("requests", "2.0.0", 11) in got
    assert not any(n == "python" for n, _, _ in got)


def test_package_json_and_lock_parsers():
    pj = '{\n "dependencies": {\n  "lodash": "4.17.15",\n  "react": "^18.0.0"\n }\n}'
    got = {(d.name, d.version, d.line) for d in parse_package_json("package.json", pj)}
    assert got == {("lodash", "4.17.15", 3), ("react", None, 4)}
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}, "node_modules/a/node_modules/b": {"version": "1.0.0"}}}, indent=1)
    deps = parse_package_lock("package-lock.json", lock)
    assert [(d.name, d.version) for d in deps] == [("lodash", "4.17.15")] and deps[0].line > 1
    big = json.dumps({"packages": {f"node_modules/p{i}": {"version": "1.0.0"} for i in range(500)}})
    assert len(parse_package_lock("package-lock.json", big)) == 300


def test_osv_hit_and_unpinned(tmp_path):
    hits, warns = run_with(tmp_path, {"requirements.txt": "flask==0.12\nrequests>=2.0\n"}, handler_ok)
    assert warns == []
    d = next(h for h in hits if h.rule_id == "DEP-001")
    assert d.severity == "high" and d.line == 1 and d.cwe == "CWE-79" and "2.2.5" in d.explanation and d.area == "deps"
    u = next(h for h in hits if h.rule_id == "DEP-002")
    assert u.severity == "info" and u.line == 2


def test_no_vuln_negative(tmp_path):
    hits, warns = run_with(tmp_path, {"requirements.txt": "requests==2.99.0\n"}, handler_ok)
    assert not [h for h in hits if h.rule_id == "DEP-001"] and warns == []


def test_pinned_no_dep002(tmp_path):
    hits, _ = run_with(tmp_path, {"requirements.txt": "requests==2.99.0\n"}, handler_ok)
    assert not [h for h in hits if h.rule_id == "DEP-002"]


def test_osv_outage_warns_without_exception(tmp_path):
    def boom(request):
        return httpx.Response(500)

    hits, warns = run_with(tmp_path, {"requirements.txt": "flask==0.12\n"}, boom)
    assert warns == ["osv_unavailable"] and not [h for h in hits if h.rule_id == "DEP-001"]


def test_fail_osv_env(tmp_path, monkeypatch):
    monkeypatch.setenv("FAIL_OSV", "1")
    called = []

    def h(request):
        called.append(1)
        return httpx.Response(200, json={"results": []})

    _, warns = run_with(tmp_path, {"requirements.txt": "flask==0.12\n"}, h)
    assert warns == ["osv_unavailable"] and not called


def test_no_pinned_deps_makes_no_request(tmp_path):
    called = []

    def h(request):
        called.append(1)
        return httpx.Response(200, json={"results": []})

    run_with(tmp_path, {"requirements.txt": "flask>=1\n"}, h)
    assert not called


def test_severity_from_cvss():
    v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert vuln_severity(v) == "critical"
    assert vuln_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert vuln_severity({}) == "medium"
