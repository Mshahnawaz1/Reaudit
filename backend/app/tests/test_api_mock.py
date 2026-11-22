import json

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

URL = "https://github.com/acme/demo"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MOCK_MODE", "1")
    monkeypatch.setenv("MOCK_DELAY_SCALE", "0.001")
    with TestClient(app) as c:
        yield c


def start(client, url=URL) -> str:
    r = client.post("/api/audit", json={"repo_url": url})
    assert r.status_code == 202
    return r.json()["job_id"]


def sse(client, job_id) -> list[tuple[str, dict]]:
    out = []
    with client.stream("GET", f"/api/audit/{job_id}/events") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        ev = None
        for line in r.iter_lines():
            if line.startswith("event:"):
                ev = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                out.append((ev, json.loads(line.split(":", 1)[1])))
    return out


def test_health(client):
    r = client.get("/api/health")
    assert r.json() == {"status": "ok", "mock": True, "model": "gemini-3.6-flash"}


def test_full_flow_and_order(client):
    jid = start(client)
    events = sse(client, jid)
    names = [e for e, _ in events]
    assert names[-1] == "done" and names.count("done") == 1
    assert all("ts" in d for _, d in events)
    stages = [(d["stage"], d["state"]) for e, d in events if e == "stage"]
    assert stages[:3] == [("ingest", "running"), ("ingest", "done"), ("deterministic", "running")]
    hits_idx = names.index("hits")
    assert hits_idx > names.index("stage")
    assert stages[-1] == ("synthesize", "done")
    assert stages.index(("verify", "running")) > stages.index(("code_agent", "done"))
    hits = next(d for e, d in events if e == "hits")
    assert hits["total"] == sum(hits["by_area"].values())
    assert [e for e, _ in sse(client, jid)] == names  # late subscriber replays

    r = client.get(f"/api/audit/{jid}").json()
    assert r["job_id"] == jid
    assert r["repo"]["owner"] == "acme" and r["repo"]["name"] == "demo"
    assert events[-1][1]["score"] == r["score"]
    fs = r["findings"]
    assert len(fs) == 12
    assert {f["severity"] for f in fs} == {"critical", "high", "medium", "low", "info"}
    assert {f["area"] for f in fs} == {"secrets", "deps", "ci", "code", "config", "meta"}
    assert sum(f["source"] == "rule+agent" for f in fs) == 1
    assert len(r["dismissed"]) == 3 and r["dropped_unverified"] == 4
    assert len(r["top5"]) == 5 and set(r["top5"]) <= {f["id"] for f in fs}
    assert all(f["verified"] is True for f in fs)
    assert r["counts"] == {s: sum(f["severity"] == s for f in fs) for s in r["counts"]}
    assert len(r["stages"]) == 7


def test_report_not_ready_then_unknown(client, monkeypatch):
    monkeypatch.setenv("MOCK_DELAY_SCALE", "1")
    jid = start(client)
    r = client.get(f"/api/audit/{jid}")
    assert r.status_code == 409 and r.json()["error"]["code"] == "job_not_ready"
    r = client.get("/api/audit/doesnotexist")
    assert r.status_code == 404 and r.json()["error"]["code"] == "job_not_found"
    assert client.get("/api/audit/doesnotexist/events").status_code == 404


def test_not_found_url(client):
    jid = start(client, URL + "/mock/not-found")
    events = sse(client, jid)
    assert events[-1][0] == "error" and events[-1][1]["code"] == "repo_not_found"
    r = client.get(f"/api/audit/{jid}")
    assert r.status_code == 422 and r.json()["error"]["code"] == "repo_not_found"


def test_degraded_url(client):
    jid = start(client, URL + "/mock/degraded")
    events = sse(client, jid)
    assert any(e == "warning" and d["code"] == "osv_unavailable" for e, d in events)
    assert ("code_agent", "degraded") in [(d["stage"], d["state"]) for e, d in events if e == "stage"]
    r = client.get(f"/api/audit/{jid}").json()
    assert next(s for s in r["stages"] if s["id"] == "code_agent")["state"] == "degraded"
    assert events[-1][0] == "done"


@pytest.mark.parametrize("body,code", [
    ({"repo_url": "https://gitlab.com/a/b"}, "unsupported_host"),
    ({"repo_url": "http://github.com/a/b"}, "invalid_url"),
    ({"repo_url": "nonsense"}, "invalid_url"),
    ({}, "invalid_url"),
    ({"repo_url": 5}, "invalid_url"),
])
def test_audit_validation(client, body, code):
    r = client.post("/api/audit", json=body)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == code
    assert "Traceback" not in r.text


def test_mock_suffix_rejected_outside_mock_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("MOCK_MODE", "0")
    monkeypatch.setattr("backend.app.config.ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as c:
        r = c.post("/api/audit", json={"repo_url": URL + "/mock/slow"})
        assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_url"


def test_issue_drafts(client):
    jid = start(client)
    sse(client, jid)
    rep = client.get(f"/api/audit/{jid}").json()
    f = rep["findings"][0]
    r = client.post(f"/api/audit/{jid}/issue-drafts", json={"finding_ids": [f["id"], rep["findings"][1]["id"]]})
    assert r.status_code == 200
    drafts = r.json()["drafts"]
    assert len(drafts) == 2 and drafts[0]["finding_id"] == f["id"]
    link = f"https://github.com/acme/demo/blob/{rep['repo']['commit']}/{f['file']}#L{f['line']}"
    assert link in drafts[0]["body_markdown"]
    assert f["snippet"] in drafts[0]["body_markdown"]
    for body in ({"finding_ids": []}, {"finding_ids": ["x"] * 11}, {"finding_ids": ["nope"]}):
        r = client.post(f"/api/audit/{jid}/issue-drafts", json=body)
        assert r.status_code == 400 and "error" in r.json()
    assert client.post("/api/audit/zzz/issue-drafts", json={"finding_ids": ["a"]}).status_code == 404


def test_cors(client):
    r = client.options("/api/audit", headers={"Origin": "http://localhost:5173",
                                              "Access-Control-Request-Method": "POST"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
