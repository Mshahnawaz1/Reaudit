from __future__ import annotations

import asyncio
import json
import os
import re
import tomllib
from dataclasses import dataclass

import httpx

from .common import FileRef, basename, read_text
from .rules_meta import make_hit
from .types import SEVERITY_ORDER, Hit

OSV_BASE = "https://api.osv.dev"
MAX_LOCK_DEPS = 300
MAX_DETAIL = 30
BATCH = 500
MAX_UNPINNED_PER_FILE = 10


@dataclass
class Dep:
    name: str
    version: str | None
    ecosystem: str
    file: str
    line: int
    snippet: str
    spec: str = ""


def _find_line(lines: list[str], name: str, start: int = 0) -> int:
    pat = re.compile(r"[\"']" + re.escape(name) + r"(?:[\"'\[<>=~!^ ;,@]|$)|^\s*" + re.escape(name) + r"\s*=", re.I)
    for i in range(start, len(lines)):
        if pat.search(lines[i]):
            return i + 1
    return 1


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*((?:[<>=!~]=?|===)\s*[^\s;,#]+(?:\s*,\s*(?:[<>=!~]=?)\s*[^\s;,#]+)*)?")


def parse_requirements(path: str, text: str) -> list[Dep]:
    deps: list[Dep] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = REQ.match(line)
        if not m:
            continue
        spec = (m.group(3) or "").replace(" ", "")
        ver = None
        em = re.fullmatch(r"(?:==|===)([A-Za-z0-9.!+_-]+)", spec)
        if em and "*" not in spec:
            ver = em.group(1)
        deps.append(Dep(_norm_py(m.group(1)), ver, "PyPI", path, i, raw.strip(), spec))
    return deps


def _pep508(s: str) -> tuple[str, str | None, str] | None:
    m = REQ.match(s)
    if not m:
        return None
    spec = (m.group(3) or "").replace(" ", "")
    em = re.fullmatch(r"(?:==|===)([A-Za-z0-9.!+_-]+)", spec)
    return _norm_py(m.group(1)), (em.group(1) if em else None), spec


def parse_pyproject(path: str, text: str) -> list[Dep]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    lines = text.splitlines()
    specs: list[str] = []
    proj = data.get("project", {})
    specs += [s for s in proj.get("dependencies", []) if isinstance(s, str)]
    for group in proj.get("optional-dependencies", {}).values():
        specs += [s for s in group if isinstance(s, str)]
    for group in data.get("dependency-groups", {}).values():
        specs += [s for s in group if isinstance(s, str)]
    deps: list[Dep] = []
    for s in specs:
        p = _pep508(s)
        if p:
            deps.append(Dep(p[0], p[1], "PyPI", path, _find_line(lines, re.split(r"[\s\[<>=!~;]", s)[0]), s, p[2]))
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    for g in poetry.get("group", {}).values():
        tables.append(g.get("dependencies", {}))
    for tbl in tables:
        for name, v in tbl.items():
            if name.lower() == "python":
                continue
            ver = v if isinstance(v, str) else (v.get("version") if isinstance(v, dict) else None)
            exact = ver if isinstance(ver, str) and re.fullmatch(r"=?=?\s*\d[\w.+-]*", ver) else None
            if exact:
                exact = exact.lstrip("= ")
            ln = _find_line(lines, name)
            deps.append(Dep(_norm_py(name), exact, "PyPI", path, ln, lines[ln - 1].strip() if lines else name, ver or ""))
    return deps


def parse_package_json(path: str, text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    deps: list[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        tbl = data.get(section)
        if not isinstance(tbl, dict):
            continue
        for name, spec in tbl.items():
            if not isinstance(spec, str):
                continue
            ver = spec if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", spec) else None
            ln = _find_line(lines, name)
            deps.append(Dep(name, ver, "npm", path, ln, lines[ln - 1].strip(), spec))
    return deps


def parse_package_lock(path: str, text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    out: list[Dep] = []
    pk = data.get("packages")
    if isinstance(pk, dict):
        for key, info in pk.items():
            if not key.startswith("node_modules/") or key.count("node_modules/") != 1 or not isinstance(info, dict):
                continue
            ver = info.get("version")
            if isinstance(ver, str) and not info.get("link"):
                out.append(Dep(key[len("node_modules/"):], ver, "npm", path, _find_line(lines, key), key, ver))
    elif isinstance(data.get("dependencies"), dict):
        for name, info in data["dependencies"].items():
            if isinstance(info, dict) and isinstance(info.get("version"), str) and re.fullmatch(r"\d[\w.+-]*", info["version"]):
                out.append(Dep(name, info["version"], "npm", path, _find_line(lines, name), name, info["version"]))
    return out[:MAX_LOCK_DEPS]


def collect_deps(files: list[FileRef]) -> list[Dep]:
    deps: list[Dep] = []
    for f in files:
        name = basename(f.path).lower()
        parser = None
        if name.startswith("requirements") and name.endswith(".txt"):
            parser = parse_requirements
        elif name == "pyproject.toml":
            parser = parse_pyproject
        elif name == "package.json":
            parser = parse_package_json
        elif name == "package-lock.json":
            parser = parse_package_lock
        if parser is None or "node_modules/" in f.path:
            continue
        text = read_text(f)
        if text is not None:
            deps.extend(parser(f.path, text))
    return deps


def unpinned_hits(deps: list[Dep]) -> list[Hit]:
    hits: list[Hit] = []
    per_file: dict[str, int] = {}
    for d in deps:
        if d.version is not None:
            continue
        is_req = basename(d.file).lower().startswith("requirements")
        if not (is_req or d.spec in ("*", "latest", "")):
            continue
        if per_file.get(d.file, 0) >= MAX_UNPINNED_PER_FILE:
            continue
        per_file[d.file] = per_file.get(d.file, 0) + 1
        hits.append(make_hit("DEP-002", d.file, d.line, d.snippet, f"`{d.name}` has no exact version ({d.spec or 'any version'}), so it cannot be checked against vulnerability databases and builds are not reproducible.", confidence=0.7))
    return hits


def _cvss3_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except (KeyError, ValueError):
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = min((1.08 if changed else 1) * (impact + 8.22 * av * ac * pr * ui), 10)
    return float(int(raw * 10 + 0.9999)) / 10


def vuln_severity(v: dict) -> str:
    ds = v.get("database_specific") or {}
    s = str(ds.get("severity", "")).upper()
    mapping = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
    if s in mapping:
        return mapping[s]
    for sev in v.get("severity") or []:
        score = _cvss3_score(str(sev.get("score", "")))
        if score is not None:
            return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return "medium"


def _fixed_versions(v: dict) -> list[str]:
    out: list[str] = []
    for a in v.get("affected") or []:
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if "fixed" in e and e["fixed"] not in out:
                    out.append(e["fixed"])
    return out


async def _post_batch(client: httpx.AsyncClient, queries: list[dict]) -> list[list[dict]]:
    last: Exception | None = None
    for _ in range(2):
        try:
            r = await client.post(f"{OSV_BASE}/v1/querybatch", json={"queries": queries}, timeout=8)
            r.raise_for_status()
            results = r.json().get("results", [])
            if len(results) != len(queries):
                raise ValueError("osv result size mismatch")
            return [x.get("vulns", []) or [] for x in results]
        except (httpx.HTTPError, ValueError) as e:
            last = e
    raise last  # type: ignore[misc]


async def _get_vuln(client: httpx.AsyncClient, vid: str) -> dict | None:
    for _ in range(2):
        try:
            r = await client.get(f"{OSV_BASE}/v1/vulns/{vid}", timeout=8)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError):
            continue
    return None


async def check_osv(deps: list[Dep], client: httpx.AsyncClient | None = None) -> tuple[list[Hit], list[str]]:
    pinned = [d for d in deps if d.version]
    if not pinned:
        return [], []
    if os.environ.get("FAIL_OSV") == "1":
        return [], ["osv_unavailable"]
    uniq: dict[tuple[str, str, str], list[Dep]] = {}
    for d in pinned:
        uniq.setdefault((d.ecosystem, d.name, d.version or ""), []).append(d)
    keys = list(uniq)
    own = client is None
    client = client or httpx.AsyncClient(timeout=8)
    try:
        vulns_by_key: dict[tuple[str, str, str], list[dict]] = {}
        try:
            for i in range(0, len(keys), BATCH):
                chunk = keys[i:i + BATCH]
                res = await _post_batch(client, [{"package": {"name": k[1], "ecosystem": k[0]}, "version": k[2]} for k in chunk])
                for k, v in zip(chunk, res):
                    if v:
                        vulns_by_key[k] = v
        except Exception:
            return [], ["osv_unavailable"]
        ids: list[str] = []
        for vs in vulns_by_key.values():
            for v in vs[:5]:
                if v["id"] not in ids:
                    ids.append(v["id"])
        ids = ids[:MAX_DETAIL]
        details = dict(zip(ids, await asyncio.gather(*(_get_vuln(client, i) for i in ids))))
    finally:
        if own:
            await client.aclose()

    hits: list[Hit] = []
    for key, vs in vulns_by_key.items():
        infos = [details.get(v["id"]) or {"id": v["id"]} for v in vs]
        sevs = [vuln_severity(i) if i.get("summary") or i.get("database_specific") or i.get("severity") else "medium" for i in infos]
        top = min(sevs, key=lambda s: SEVERITY_ORDER[s])
        fixes: list[str] = []
        for i in infos:
            for fv in _fixed_versions(i):
                if fv not in fixes:
                    fixes.append(fv)
        cwe = next((c for i in infos for c in ((i.get("database_specific") or {}).get("cwe_ids") or [])), None)
        listing = "; ".join(f"{i['id']}" + (f" ({i['summary'][:80]})" if i.get("summary") else "") for i in infos[:5])
        more = f" and {len(vs) - 5} more" if len(vs) > 5 else ""
        for d in uniq[key]:
            expl = f"`{d.name}` {d.version} has {len(vs)} known advisories: {listing}{more}."
            if fixes:
                expl += f" Fixed in: {', '.join(fixes[:5])}."
            h = make_hit("DEP-001", d.file, d.line, d.snippet, expl, severity=top, confidence=0.95, cwe=cwe,
                         title=f"{d.name} {d.version} has known vulnerabilities")
            hits.append(h)
    return hits, []
