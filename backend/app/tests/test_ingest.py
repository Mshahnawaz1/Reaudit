import subprocess
from pathlib import Path

import pytest

from backend.app.errors import AppError
from backend.app.ingest import (
    RepoRef, build_snapshot, classify, ingest_repo, map_clone_error, parse_repo_url,
)


@pytest.mark.parametrize("url,owner,name,branch", [
    ("https://github.com/octo/hello", "octo", "hello", None),
    ("https://github.com/octo/hello.git", "octo", "hello", None),
    ("https://github.com/octo/hello/", "octo", "hello", None),
    ("  https://github.com/octo/hello.js  ", "octo", "hello.js", None),
    ("https://github.com/octo/hello/tree/feature/x-1", "octo", "hello", "feature/x-1"),
    ("https://GitHub.com/octo/hello", "octo", "hello", None),
])
def test_parse_ok(url, owner, name, branch):
    r = parse_repo_url(url)
    assert (r.owner, r.name, r.branch) == (owner, name, branch)
    assert r.clone_url == f"https://github.com/{owner}/{name}.git"


@pytest.mark.parametrize("url,code", [
    ("", "invalid_url"),
    ("not a url", "invalid_url"),
    ("http://github.com/a/b", "invalid_url"),
    ("git@github.com:a/b.git", "invalid_url"),
    ("ssh://git@github.com/a/b", "invalid_url"),
    ("file:///etc/passwd", "invalid_url"),
    ("https://user:pw@github.com/a/b", "invalid_url"),
    ("https://github.com@evil.com/a/b", "invalid_url"),
    ("https://github.com:8443/a/b", "invalid_url"),
    ("https://github.com/a", "invalid_url"),
    ("https://github.com/a/b/issues", "invalid_url"),
    ("https://github.com/a/b?x=1", "invalid_url"),
    ("https://github.com/a/b#frag", "invalid_url"),
    ("https://github.com/a/b/tree/../x", "invalid_url"),
    ("https://github.com/a/b/tree/-evil", "invalid_url"),
    ("https://github.com/a/..", "invalid_url"),
    ("https://github.com/a/b c", "invalid_url"),
    ("https://github.com/a/b;rm -rf", "invalid_url"),
    ("https://gitlab.com/a/b", "unsupported_host"),
    ("https://github.com.evil.com/a/b", "unsupported_host"),
    ("https://evilgithub.com/a/b", "unsupported_host"),
])
def test_parse_rejects(url, code):
    with pytest.raises(AppError) as e:
        parse_repo_url(url)
    assert e.value.code == code
    assert e.value.status == 400


@pytest.mark.parametrize("path,area,lang", [
    (".github/workflows/ci.yml", "ci", "other"),
    ("src/app.py", "app_code", "py"),
    ("web/App.tsx", "app_code", "ts"),
    ("web/index.mjs", "app_code", "js"),
    ("package.json", "manifest", "other"),
    ("sub/requirements-dev.txt", "manifest", "other"),
    ("uv.lock", "manifest", "other"),
    (".env", "env", "other"),
    (".env.production", "env", "other"),
    ("Dockerfile", "docker", "other"),
    ("docker-compose.yml", "docker", "other"),
    ("README.md", "other", "other"),
    ("main.go", "other", "other"),
])
def test_classify(path, area, lang):
    assert classify(path) == (area, lang)


def _write(root: Path, rel: str, data: bytes | str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())


def test_snapshot_skips_and_coverage(tmp_path: Path):
    _write(tmp_path, "app.py", "print(1)\n")
    _write(tmp_path, "main.go", "package main\n")
    _write(tmp_path, ".github/workflows/ci.yml", "on: push\n")
    _write(tmp_path, "logo.png", b"\x89PNG\0\0")
    _write(tmp_path, "data.dat", b"abc\0def")
    _write(tmp_path, "big.py", "x = 1\n" * 50_000)
    _write(tmp_path, "static/app.min.js", "var a=1;")
    _write(tmp_path, "node_modules/x/index.js", "1")
    _write(tmp_path, "node_modules/x/b.js", "1")
    (tmp_path / "link.py").symlink_to(tmp_path / "app.py")
    snap = build_snapshot(tmp_path, "abc", "main")
    assert {f.path for f in snap.files} == {"app.py", "main.go", ".github/workflows/ci.yml"}
    c = snap.coverage
    assert c.files_scanned == 3
    assert c.files_total == c.files_scanned + c.files_skipped
    assert c.skipped_reasons == {"binary": 2, "ignored_dir": 2, "minified": 1, "symlink": 1, "too_large": 1}
    assert c.languages == ["go", "python"]
    assert c.reduced_coverage_languages == ["go"]
    assert c.caps_hit == []


def test_snapshot_caps_keep_high_priority(tmp_path: Path):
    for i in range(10):
        _write(tmp_path, f"src/m{i}.py", "x=1\n")
    _write(tmp_path, ".github/workflows/ci.yml", "on: push\n")
    snap = build_snapshot(tmp_path, max_files=3)
    assert len(snap.files) == 3
    assert ".github/workflows/ci.yml" in {f.path for f in snap.files}
    assert snap.coverage.caps_hit == ["max_files"]
    assert snap.coverage.skipped_reasons["cap_max_files"] == 8
    snap = build_snapshot(tmp_path, max_total_bytes=10)
    assert "max_bytes" in snap.coverage.caps_hit


def _git(cwd: Path, *args: str):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True,
                   capture_output=True)


def make_local_clone(src: Path):
    async def clone(ref: RepoRef, dest: Path) -> None:
        subprocess.run(["git", "clone", "--depth", "1", f"file://{src}", str(dest)], check=True,
                       capture_output=True)
    return clone


@pytest.fixture
def local_repo(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-b", "main")
    _write(src, "app.py", "print('hi')\n")
    _write(src, ".env", "A=1\n")
    _git(src, "add", "-A")
    _git(src, "commit", "-m", "init")
    return src


@pytest.mark.asyncio
async def test_ingest_local_clone_and_cleanup(local_repo: Path, tmp_path: Path):
    tmp_root = tmp_path / "work"
    tmp_root.mkdir()
    async with ingest_repo(RepoRef("o", "r"), make_local_clone(local_repo), tmp_root) as snap:
        assert len(snap.commit) == 40
        assert snap.branch == "main"
        assert {f.path for f in snap.files} == {"app.py", ".env"}  # .git excluded
        assert (snap.root / "app.py").exists()
        root = snap.root
    assert not root.exists()
    assert list(tmp_root.iterdir()) == []


@pytest.mark.asyncio
async def test_ingest_cleanup_on_error_and_empty(tmp_path: Path):
    tmp_root = tmp_path / "work"
    tmp_root.mkdir()

    async def empty(ref, dest):
        dest.mkdir(parents=True)

    with pytest.raises(AppError) as e:
        async with ingest_repo(RepoRef("o", "r"), empty, tmp_root):
            pass
    assert e.value.code == "repo_empty"
    assert list(tmp_root.iterdir()) == []


@pytest.mark.asyncio
async def test_ingest_too_large(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("backend.app.ingest.MAX_REPO_BYTES", 10)

    async def big(ref, dest):
        _write(dest, "a.txt", "x" * 100)

    with pytest.raises(AppError) as e:
        async with ingest_repo(RepoRef("o", "r"), big, tmp_path):
            pass
    assert e.value.code == "repo_too_large"


@pytest.mark.parametrize("stderr,code", [
    ("fatal: repository 'https://github.com/a/b.git/' not found", "repo_not_found"),
    ("fatal: Remote branch nope not found in upstream origin", "repo_not_found"),
    ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", "repo_not_found"),
    ("remote: Permission denied", "repo_private_or_forbidden"),
    ("fatal: something weird", "internal_error"),
])
def test_map_clone_error(stderr, code):
    assert map_clone_error(stderr).code == code
