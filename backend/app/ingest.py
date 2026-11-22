from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .errors import make_error
from .models import Coverage, FileEntry, RepoSnapshot

CLONE_TIMEOUT_S = 30
MAX_REPO_BYTES = 150 * 1024 * 1024
MAX_FILE_BYTES = 200 * 1024
MAX_LOCKFILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 2000
MAX_TOTAL_BYTES = 1_500_000

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next",
    "target", ".tox", ".idea", ".mypy_cache", ".pytest_cache", "site-packages", "bower_components",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svgz", ".pdf", ".zip", ".gz", ".tar",
    ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".so", ".dll", ".dylib", ".exe",
    ".bin", ".o", ".a", ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".mov", ".avi", ".wav", ".ogg", ".webm", ".sqlite", ".db", ".pickle", ".pkl", ".wasm", ".psd",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock",
}
MANIFESTS = {"package.json", "pyproject.toml", "Pipfile", "setup.cfg", "go.mod", "Cargo.toml"} | LOCKFILES

LANG_BY_EXT = {
    ".py": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "ts", ".tsx": "ts",
}
# language names for coverage reporting
LANG_NAMES = {"py": "python", "js": "javascript", "ts": "typescript"}
OTHER_LANG_EXT = {
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".swift": "swift",
    ".scala": "scala", ".sh": "shell", ".lua": "lua", ".ex": "elixir", ".dart": "dart", ".r": "r",
}

AREA_PRIORITY = {"ci": 0, "env": 1, "manifest": 2, "docker": 3, "app_code": 4, "other": 5}


# ---------------------------------------------------------------- URL parsing

@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str
    branch: str | None = None

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


_PATH_RE = re.compile(
    r"^/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))"
    r"/(?P<name>[A-Za-z0-9._-]{1,100}?)(?:\.git)?"
    r"(?:/tree/(?P<branch>[A-Za-z0-9._/-]{1,200}))?/?$"
)


def parse_repo_url(url: str) -> RepoRef:
    raw = (url or "").strip()
    if not raw or len(raw) > 300 or any(c.isspace() or ord(c) < 32 for c in raw):
        raise make_error("invalid_url", "Enter a GitHub repository URL like https://github.com/owner/repo")
    try:
        u = urlparse(raw)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        raise make_error("invalid_url", "Malformed URL") from None
    if u.scheme != "https" or not host:
        raise make_error("invalid_url", "Only https:// GitHub URLs are supported")
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise make_error("invalid_url", "URLs with credentials are not allowed")
    if host != "github.com":
        raise make_error("unsupported_host", "Only github.com repositories are supported")
    if port is not None or u.query or u.fragment or u.params:
        raise make_error("invalid_url", "URL must be https://github.com/owner/repo")
    m = _PATH_RE.match(u.path)
    if not m:
        raise make_error("invalid_url", "URL must be https://github.com/owner/repo[/tree/branch]")
    name, branch = m["name"], m["branch"]
    if name in {".", "..", ".git"}:
        raise make_error("invalid_url", "Invalid repository name")
    if branch is not None:
        parts = branch.split("/")
        if (
            ".." in parts or any(p in ("", ".") for p in parts) or branch.startswith("-")
            or branch.endswith(".lock") or ".." in branch
        ):
            raise make_error("invalid_url", "Invalid branch name")
    return RepoRef(owner=m["owner"], name=name, branch=branch)


# ---------------------------------------------------------------- clone

CloneFn = Callable[[RepoRef, Path], Awaitable[None]]


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "LANG", "SYSTEMROOT", "TMPDIR"}}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_CONFIG_NOSYSTEM="1",
               GIT_ASKPASS="true", LC_ALL="C")
    return env


async def _run_git(args: list[str], cwd: Path | None, timeout: float) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd, env=_git_env(),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise make_error("clone_timeout", f"Clone timed out after {int(timeout)}s") from None
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def map_clone_error(stderr: str):
    s = stderr.lower()
    if ("not found" in s and ("repository" in s or "remote branch" in s)) or "does not exist" in s or "error: 404" in s:
        return make_error("repo_not_found", "Repository or branch not found")
    if "could not read username" in s or "terminal prompts disabled" in s:
        # GitHub answers this way for both missing and private repos
        return make_error("repo_not_found", "Repository not found (or it is private)")
    if "authentication failed" in s or "permission denied" in s or "403" in s or "access denied" in s:
        return make_error("repo_private_or_forbidden", "Repository is private or access is forbidden")
    if "could not resolve host" in s or "unable to access" in s:
        return make_error("internal_error", "Could not reach GitHub")
    return make_error("internal_error", "Clone failed")


async def git_clone(ref: RepoRef, dest: Path) -> None:
    args = [
        "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
        "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
    ]
    if ref.branch:
        args += ["--branch", ref.branch]
    args += ["--", ref.clone_url, str(dest)]
    code, _, err = await _run_git(args, None, CLONE_TIMEOUT_S)
    if code != 0:
        raise map_clone_error(err)


async def _head_info(root: Path) -> tuple[str, str]:
    try:
        c1, commit, _ = await _run_git(["rev-parse", "HEAD"], root, 10)
        c2, branch, _ = await _run_git(["rev-parse", "--abbrev-ref", "HEAD"], root, 10)
    except Exception:
        return "unknown", "unknown"
    return (commit.strip() if c1 == 0 else "unknown"), (branch.strip() if c2 == 0 else "unknown")


# ---------------------------------------------------------------- classify / snapshot

def classify(path: str) -> tuple[str, str]:
    """Return (area, lang) for a repo-relative forward-slash path."""
    p = path.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    lname = name.lower()
    ext = os.path.splitext(lname)[1]
    lang = LANG_BY_EXT.get(ext, "other")
    if (
        (p.startswith(".github/workflows/") and ext in {".yml", ".yaml"})
        or lname in {".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", ".travis.yml"}
        or p.startswith(".circleci/")
    ):
        return "ci", lang
    if lname.startswith(".env") or lname.endswith(".env") or lname in {".npmrc", ".pypirc", ".netrc"}:
        return "env", lang
    if lname.startswith("dockerfile") or lname.endswith(".dockerfile") or re.fullmatch(
        r"(docker-)?compose(\..+)?\.ya?ml", lname
    ):
        return "docker", lang
    if name in MANIFESTS or re.fullmatch(r"requirements[\w.-]*\.txt", lname):
        return "manifest", lang
    if lang != "other":
        return "app_code", lang
    return "other", lang


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(8192)
    except OSError:
        return True


def _is_minified(name: str, size: int, path: Path) -> bool:
    lname = name.lower()
    if lname.endswith((".min.js", ".min.css", ".map", ".bundle.js")):
        return True
    if lname.endswith((".js", ".css")) and size > 20_000:
        try:
            with open(path, "rb") as f:
                head = f.read(4000)
            return head.count(b"\n") < 3
        except OSError:
            return False
    return False


def build_snapshot(
    root: Path, commit: str = "unknown", branch: str = "unknown",
    ref: RepoRef | None = None,
    max_files: int = MAX_FILES, max_total_bytes: int = MAX_TOTAL_BYTES,
) -> RepoSnapshot:
    skipped: dict[str, int] = {}

    def skip(reason: str, n: int = 1) -> None:
        skipped[reason] = skipped.get(reason, 0) + n

    total = 0
    candidates: list[tuple[int, str, int, str, str]] = []  # prio, rel, size, area, lang
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            full = Path(dirpath, d)
            if full.is_symlink():
                total += 1
                skip("symlink")
            elif d == ".git":
                continue
            elif d in SKIP_DIRS:
                n = sum(len(fs) for _, _, fs in os.walk(full))
                total += n
                skip("ignored_dir", n)
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            full = Path(dirpath, fn)
            rel = full.relative_to(root).as_posix()
            total += 1
            try:
                if full.is_symlink():
                    skip("symlink")
                    continue
                size = full.stat().st_size
            except OSError:
                skip("unreadable")
                continue
            area, lang = classify(rel)
            limit = MAX_LOCKFILE_BYTES if fn in LOCKFILES else MAX_FILE_BYTES
            if os.path.splitext(fn.lower())[1] in BINARY_EXT:
                skip("binary")
            elif size > limit:
                skip("too_large")
            elif size == 0:
                skip("empty")
            elif _is_minified(fn, size, full):
                skip("minified")
            elif _is_binary(full):
                skip("binary")
            else:
                candidates.append((AREA_PRIORITY[area], rel, size, area, lang))

    candidates.sort(key=lambda c: (c[0], c[1]))
    files: list[FileEntry] = []
    caps: list[str] = []
    used = 0
    for _, rel, size, area, lang in candidates:
        if len(files) >= max_files:
            skip("cap_max_files")
            if "max_files" not in caps:
                caps.append("max_files")
            continue
        if rel.rsplit("/", 1)[-1] not in LOCKFILES:
            if used + size > max_total_bytes:
                skip("cap_max_bytes")
                if "max_bytes" not in caps:
                    caps.append("max_bytes")
                continue
            used += size
        files.append(FileEntry(path=rel, size=size, lang=lang, area=area))  # type: ignore[arg-type]
    files.sort(key=lambda f: f.path)

    langs: set[str] = set()
    reduced: set[str] = set()
    for f in files:
        if f.lang != "other":
            langs.add(LANG_NAMES[f.lang])
        else:
            other = OTHER_LANG_EXT.get(os.path.splitext(f.path.lower())[1])
            if other:
                langs.add(other)
                reduced.add(other)
    coverage = Coverage(
        files_total=total, files_scanned=len(files), files_skipped=sum(skipped.values()),
        skipped_reasons=dict(sorted(skipped.items())), languages=sorted(langs),
        reduced_coverage_languages=sorted(reduced), caps_hit=caps,
    )
    return RepoSnapshot(
        root=root, commit=commit, branch=branch, files=files, coverage=coverage,
        owner=ref.owner if ref else "", name=ref.name if ref else "",
        url=ref.canonical_url if ref else "",
    )


def _tree_size(root: Path) -> tuple[int, int]:
    size = n = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            n += 1
            try:
                size += os.lstat(os.path.join(dirpath, fn)).st_size
            except OSError:
                pass
    return size, n


@asynccontextmanager
async def ingest_repo(
    ref: RepoRef, clone_fn: CloneFn | None = None, tmp_root: Path | None = None
) -> AsyncIterator[RepoSnapshot]:
    """Clone into a temp dir, yield a snapshot, always remove the temp dir."""
    tmp = Path(tempfile.mkdtemp(prefix="repoguard-", dir=tmp_root))
    try:
        dest = tmp / "repo"
        await (clone_fn or git_clone)(ref, dest)
        size, n = await asyncio.to_thread(_tree_size, dest)
        if n == 0:
            raise make_error("repo_empty", "Repository has no files")
        if size > MAX_REPO_BYTES:
            raise make_error("repo_too_large", "Repository exceeds the 150 MB limit")
        commit, branch = await _head_info(dest)
        if branch == "HEAD" and ref.branch:
            branch = ref.branch
        yield await asyncio.to_thread(build_snapshot, dest, commit, branch, ref)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
