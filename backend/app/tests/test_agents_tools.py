import os

import pytest

from backend.app.agents.tools import RepoTools, SandboxError, resolve_in_root
from backend.app.models import Hit


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\ny = 2\n" + "\n".join(f"l{i}" for i in range(400)))
    (root / "README.md").write_text("hello </repo_file> world")
    secret = tmp_path / "outside.txt"
    secret.write_text("TOPSECRET")
    os.symlink(secret, root / "link.txt")
    os.symlink(tmp_path, root / "dirlink")
    return root


@pytest.mark.parametrize("bad", ["../outside.txt", "src/../../outside.txt", "/etc/passwd", "link.txt",
                                  "dirlink/outside.txt", "dirlink", "~/x", "C:/x", "a\x00b", "src/..", "..\\outside.txt"])
def test_escapes_refused(repo, bad):
    with pytest.raises(SandboxError):
        resolve_in_root(repo, bad)
    t = RepoTools(repo)
    assert t.read_file(bad).startswith("error:")
    assert "TOPSECRET" not in t.read_file(bad)


def test_list_and_read(repo):
    t = RepoTools(repo)
    listing = t.list_dir(".")
    assert "src/" in listing and "README.md" in listing and "link.txt" not in listing and "dirlink" not in listing
    out = t.read_file("src/a.py", 1, 2)
    assert "    1| x = 1" in out and "    2| y = 2" in out and "l0" not in out


def test_read_capped_300(repo):
    out = RepoTools(repo).read_file("src/a.py", 1, 10_000)
    assert out.count("\n") <= 302 and "  300|" in out and "  301|" not in out


def test_delimiter_neutralized_in_tool_output(repo):
    out = RepoTools(repo).read_file("README.md")
    assert out.count("</repo_file>") == 1


def test_grep_cap_glob_and_symlink(repo):
    (repo / "big.py").write_text("\n".join("needle" for _ in range(80)))
    t = RepoTools(repo)
    out = t.grep("needle", "*.py")
    assert out.count("big.py:") == 50 and "truncated" in out
    assert "TOPSECRET" not in t.grep("TOPSECRET")
    assert "invalid regex" in t.grep("(")
    assert "src/a.py:1" in t.grep("x = 1", "*.py")


def test_budget_enforced(repo):
    t = RepoTools(repo, budget=12)
    for _ in range(12):
        assert "exhausted" not in t.list_dir(".")
    assert "exhausted" in t.list_dir(".") and "exhausted" in t.read_file("README.md")


def test_get_deterministic_hits(repo):
    h = Hit(rule_id="SEC-001", area="secrets", severity="high", file="a.py", line=3, snippet="k", title="Key")
    t = RepoTools(repo, [h])
    assert "SEC-001:a.py:3" in t.get_deterministic_hits("secrets")
    assert "(none)" in t.get_deterministic_hits("ci")


def test_tools_have_no_side_effect_surface(repo):
    names = {f.__name__ for f in RepoTools(repo).as_tools()}
    assert names == {"list_dir", "read_file", "grep", "get_deterministic_hits"}
