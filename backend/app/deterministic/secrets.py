from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .common import FileRef, basename, read_text
from .rules_meta import make_hit
from .types import Hit

SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "pipfile.lock",
    "composer.lock", "cargo.lock", "gemfile.lock", "go.sum", "npm-shrinkwrap.json",
}
SKIP_EXT = (
    ".min.js", ".min.css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
    ".gz", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".lock", ".sum", ".pyc", ".so", ".bin", ".exe",
)
ENV_LIKE_EXT = (".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".sh", ".txt")
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tmpl")
SENSITIVE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.json", ".pypirc", ".netrc",
    ".htpasswd", "service-account.json", "serviceaccount.json", "secrets.json", "secrets.yml",
    "secrets.yaml", ".git-credentials",
}
PLACEHOLDERS = (
    "example", "your_", "your-", "yourkey", "xxxx", "changeme", "change_me", "change-me", "placeholder",
    "dummy", "sample", "<", "todo", "replace", "fake", "redacted", "****", "insert", "my_secret",
    "mysecret", "foobar", "not-a-real",
)
COMMON_WEAK = {"password", "secret", "token", "test", "testing", "admin", "default", "12345678", "undefined"}


def redact(value: str) -> str:
    return value[:4] + "…"


def is_placeholder(value: str) -> bool:
    v = value.lower()
    if any(p in v for p in PLACEHOLDERS) or v in COMMON_WEAK:
        return True
    return len(set(v)) <= 2


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


@dataclass
class Match:
    rule: str
    value: str
    name: str = ""
    redact_snippet: bool = True


SPECIFIC: list[tuple[str, re.Pattern[str], int]] = [
    ("SEC-001", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    ("SEC-012", re.compile(r"(?i)aws_?secret_?(?:access_?)?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1),
    ("SEC-002", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 1),
    ("SEC-003", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{16,})\b"), 1),
    ("SEC-004", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})"), 1),
    ("SEC-004", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)"), 1),
    ("SEC-005", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), 1),
    ("SEC-007", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"), 1),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")
KEYWORD = r"(?:api[_-]?key|apikey|secret|passw(?:or)?d|passwd|pwd|token|auth[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)"
GENERIC_QUOTED = re.compile(r"(?i)\b([\w.-]*" + KEYWORD + r"[\w.-]*)[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']")
GENERIC_BARE = re.compile(r"(?i)^\s*(?:export\s+)?([\w.-]*" + KEYWORD + r"[\w.-]*)\s*[:=]\s*([^\s\"'#]{8,})\s*(?:#.*)?$")
QUOTED = re.compile(r"[\"']([A-Za-z0-9+/=_\-]{20,100})[\"']")
NOT_VALUE_PREFIX = ("$", "{", "<", "%", "os.", "process.", "env", "config", "settings", "self.", "request", "getenv", "null", "none", "true", "false", "http", "./", "../", "/")
NOISE_LINE = ("integrity", "sha512", "sha256", "sha1-", "checksum", "data:image", "import ", "require(", "from ", "xmlns", "href=")
HEX = re.compile(r"^[0-9a-fA-F]+$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_reference(value: str) -> bool:
    v = value.lower()
    return v.startswith(NOT_VALUE_PREFIX) or "(" in v or ")" in v or "${" in v or "{{" in v or v.endswith(("[", "]"))


def scan_line(line: str, env_like: bool, allow_entropy: bool = True) -> list[Match]:
    if len(line) > 2000:
        return []
    out: list[Match] = []
    covered: list[str] = []
    for rule, pat, grp in SPECIFIC:
        for m in pat.finditer(line):
            out.append(Match(rule, m.group(grp)))
            covered.append(m.group(grp))
    if PRIVATE_KEY.search(line):
        out.append(Match("SEC-006", PRIVATE_KEY.search(line).group(0), redact_snippet=False))  # type: ignore[union-attr]

    def seen(v: str) -> bool:
        return any(v in c or c in v for c in covered)

    for m in GENERIC_QUOTED.finditer(line):
        name, value = m.group(1), m.group(2)
        if not _is_reference(value) and not seen(value):
            out.append(Match("SEC-008", value, name))
            covered.append(value)
    if env_like:
        m = GENERIC_BARE.match(line)
        if m and not _is_reference(m.group(2)) and not seen(m.group(2)):
            out.append(Match("SEC-008", m.group(2), m.group(1)))
            covered.append(m.group(2))
    if allow_entropy and not any(n in line.lower() for n in NOISE_LINE):
        for m in QUOTED.finditer(line):
            v = m.group(1)
            if seen(v) or HEX.match(v) or UUID.match(v) or v.count("/") >= 2:
                continue
            if not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)) or (v.islower() and "-" in v):
                continue
            if entropy(v) >= 4.3:
                out.append(Match("SEC-009", v))
                covered.append(v)
    return out


def scrub(line: str, matches: list[Match]) -> str:
    s = line.strip()
    for m in sorted(matches, key=lambda x: -len(x.value)):
        if m.redact_snippet:
            s = s.replace(m.value, redact(m.value))
    return s[:200]


def is_env_file(name: str) -> bool:
    n = name.lower()
    if n == ".env":
        return True
    return n.startswith(".env.") and not n.endswith(EXAMPLE_SUFFIXES)


def scan_secrets(files: list[FileRef]) -> list[Hit]:
    hits: list[Hit] = []
    env_files: list[tuple[str, int]] = []
    gitignore: tuple[str, list[str]] | None = None
    env_usage: tuple[str, int] | None = None

    for f in files:
        name = basename(f.path)
        low = name.lower()
        if low in SKIP_NAMES or low.endswith(SKIP_EXT):
            continue
        text = read_text(f)
        if text is None:
            continue
        lines = text.splitlines()
        if low == ".gitignore" and "/" not in f.path:
            gitignore = (f.path, lines)
        hits.extend(_file_level(f, low, lines, env_files))
        env_like = low.endswith(ENV_LIKE_EXT) or low.startswith(".env") or "." not in low
        allow_entropy = not low.endswith((".md", ".rst", ".txt", ".csv", ".json", ".ipynb"))
        for i, line in enumerate(lines, 1):
            if env_usage is None and low.endswith((".py", ".js", ".ts", ".mjs", ".cjs")) and re.search(r"load_dotenv|dotenv\.config|require\(['\"]dotenv|from dotenv|import dotenv", line):
                env_usage = (f.path, i)
            ms = scan_line(line, env_like, allow_entropy)
            if not ms:
                continue
            snippet = scrub(line, ms)
            for m in ms:
                hits.append(_hit_for(f.path, i, m, snippet))
    hits.extend(_gitignore_gap(gitignore, env_files, env_usage))
    return hits


def _hit_for(path: str, line: int, m: Match, snippet: str) -> Hit:
    placeholder = m.rule != "SEC-006" and is_placeholder(m.value)
    label = f" ({m.name})" if m.name else ""
    expl = f"A value that looks like a credential{label} starting with `{redact(m.value)}` is hardcoded in the file."
    if m.rule == "SEC-006":
        expl = "A private key block starts here; anyone with repo read access can use it."
    if placeholder:
        return make_hit(m.rule, path, line, snippet, expl + " The value looks like a placeholder, so it is likely not a live secret.", severity="low", confidence=0.2)
    conf = 0.9 if m.rule not in ("SEC-008", "SEC-009") else (0.5 if m.rule == "SEC-009" else 0.65)
    if m.rule == "SEC-008" and m.value.islower() and m.value.isalpha():
        conf = 0.35
    return make_hit(m.rule, path, line, snippet, expl, confidence=conf)


def _file_level(f: FileRef, low: str, lines: list[str], env_files: list[tuple[str, int]]) -> list[Hit]:
    out: list[Hit] = []
    if is_env_file(low):
        first = None
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if s and not s.startswith("#") and "=" in s:
                first = (i, s)
                break
        if first:
            key, _, val = first[1].partition("=")
            val = val.strip().strip("\"'")
            snippet = f"{key.strip()}={redact(val) if val else ''}"
            env_files.append((f.path, first[0]))
            out.append(make_hit("SEC-010", f.path, first[0], snippet, f"Environment file `{basename(f.path)}` with {sum(1 for l in lines if '=' in l and not l.strip().startswith('#'))} assignment(s) is committed; env files usually hold live credentials."))
    elif low in SENSITIVE_NAMES:
        out.append(make_hit("SEC-010", f.path, 1, lines[0][:4] + "…" if lines else "(empty)", f"`{basename(f.path)}` is a credential file and should not be committed."))
    elif low == ".npmrc":
        for i, ln in enumerate(lines, 1):
            m = re.search(r"_authToken\s*=\s*(\S+)", ln)
            if m and not m.group(1).startswith(("${", "$")):
                out.append(make_hit("SEC-010", f.path, i, ln.replace(m.group(1), redact(m.group(1))).strip(), "`.npmrc` contains a hardcoded registry auth token."))
    return out


def _gitignore_gap(gitignore: tuple[str, list[str]] | None, env_files: list[tuple[str, int]], usage: tuple[str, int] | None) -> list[Hit]:
    if not env_files and not usage:
        return []
    if gitignore:
        for ln in gitignore[1]:
            s = ln.strip().lstrip("/")
            if s in (".env", ".env*", ".env.*", "*.env", ".env/", "**/.env") or s.startswith(".env"):
                if not s.startswith("!"):
                    return []
        line_no, snippet = 1, (gitignore[1][0].strip() if gitignore[1] else "(empty file)")
        path = gitignore[0]
    elif env_files:
        return []
    else:
        assert usage
        path, line_no, snippet = usage[0], usage[1], "(no .gitignore found)"
    why = "env files are committed" if env_files else "the code loads a .env file"
    return [make_hit("SEC-011", path, line_no, snippet, f".gitignore has no entry for `.env`, and {why}, so secrets can be committed accidentally.")]
