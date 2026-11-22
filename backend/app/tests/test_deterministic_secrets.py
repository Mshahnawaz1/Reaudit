import asyncio
from pathlib import Path

import pytest

from backend.app.deterministic import run_deterministic

GH = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cD1fG3hJ5"
SLACK = "xoxb-" + "1234567890-" + "abcdefghijKLMNOP"
GOOGLE = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
STRIPE = "sk_live_" + "51HxYz9AbCdEfGhIjKlMnOpQr"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "Q9zK3mLpT2"
JWT = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJhYmNkZWZnaCJ9." + "dGhpc2lzYXNpZ25hdHVyZQ"
AKIA = "AKIA" + "QWERTYUIOPASDFGH"
ENTROPY = "Zx9Qp7Lm2Vb8Nc4Rt6Yw1Ks5Hd3Jf0Ge"


def scan(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return asyncio.run(run_deterministic(tmp_path))[0]


def ids(hits):
    return {h.rule_id for h in hits}


@pytest.mark.parametrize(
    "rule,line",
    [
        ("SEC-001", f'k = "{AKIA}"'),
        ("SEC-012", f'aws_secret_access_key = "{AWS_SECRET}"'),
        ("SEC-002", f't = "{GH}"'),
        ("SEC-003", f'stripe = "{STRIPE}"'),
        ("SEC-004", f'slack = "{SLACK}"'),
        ("SEC-005", f'g = "{GOOGLE}"'),
        ("SEC-006", "-----BEGIN RSA PRIVATE KEY-----"),
        ("SEC-007", f'j = "{JWT}"'),
        ("SEC-008", 'db_password = "s3cr3tPassw0rd!x"'),
        ("SEC-009", f'blob = "{ENTROPY}"'),
    ],
)
def test_secret_rules_positive_and_redacted(tmp_path, rule, line):
    hits = [h for h in scan(tmp_path, {"src/a.py": f"x = 1\n{line}\n"}) if h.rule_id == rule]
    assert hits, rule
    h = hits[0]
    assert h.line == 2 and h.file == "src/a.py" and h.area == "secrets"
    if rule != "SEC-006":
        for secret in (AKIA, AWS_SECRET, GH, STRIPE, SLACK, GOOGLE, JWT, ENTROPY, "s3cr3tPassw0rd!x"):
            blob = h.model_dump_json()
            assert secret not in blob


@pytest.mark.parametrize(
    "content",
    [
        'x = os.environ["API_KEY"]\n',
        'password = os.environ.get("PASSWORD")\n',
        'name = "some-kebab-case-identifier-here"\n',
        'sha = "0123456789abcdef0123456789abcdef01234567"\n',
        'id = "123e4567-e89b-12d3-a456-426614174000"\n',
        "api_key = ''\n",
    ],
)
def test_secret_negatives(tmp_path, content):
    hits = scan(tmp_path, {"a.py": content})
    assert not [h for h in hits if h.area == "secrets"]


def test_lockfile_noise_skipped(tmp_path):
    noise = '{"integrity": "sha512-' + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cD1fG3hJ5kL7mN9pQ" + '"}'
    hits = scan(tmp_path, {"package-lock.json": f'token = "{GH}"\n{noise}\n', "yarn.lock": f'x "{AKIA}"'})
    assert not [h for h in hits if h.area == "secrets"]


def test_placeholder_low_confidence_but_emitted(tmp_path):
    hits = scan(tmp_path, {"a.py": 'k = "AKIAIOSFODNN7EXAMPLE"\napi_key = "your_key_here_please"\n'})
    sec = [h for h in hits if h.area == "secrets"]
    assert {h.rule_id for h in sec} >= {"SEC-001", "SEC-008"}
    assert all(h.confidence <= 0.3 and h.severity == "low" for h in sec)


def test_env_file_committed(tmp_path):
    hits = scan(tmp_path, {".env": f"API_TOKEN={GH}\nDEBUG=1\n", ".gitignore": "node_modules\n"})
    h = next(h for h in hits if h.rule_id == "SEC-010")
    assert h.file == ".env" and h.line == 1 and GH not in h.model_dump_json()
    assert "SEC-011" in ids(hits)


def test_env_example_not_flagged(tmp_path):
    hits = scan(tmp_path, {".env.example": "API_TOKEN=\nFOO=bar\n", ".gitignore": ".env\n"})
    assert "SEC-010" not in ids(hits) and "SEC-011" not in ids(hits)


def test_sensitive_names_and_npmrc(tmp_path):
    hits = scan(tmp_path, {"id_rsa": "abcdef\n", ".npmrc": "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop\n"})
    assert len([h for h in hits if h.rule_id == "SEC-010"]) == 2
    ok = scan(tmp_path / "ok", {".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"})
    assert "SEC-010" not in ids(ok)


def test_gitignore_gap_negative_and_positive(tmp_path):
    use = {"app.py": "from dotenv import load_dotenv\nload_dotenv()\n"}
    pos = scan(tmp_path / "p", {**use, ".gitignore": "*.pyc\n"})
    assert next(h for h in pos if h.rule_id == "SEC-011").file == ".gitignore"
    neg = scan(tmp_path / "n", {**use, ".gitignore": "*.pyc\n.env\n"})
    assert "SEC-011" not in ids(neg)


def test_duck_typed_files(tmp_path):
    (tmp_path / "a.py").write_text(f'k = "{AKIA}"\n')

    class F:
        path, size, lang, area = "a.py", 10, "py", "app_code"

    hits, warns = asyncio.run(run_deterministic(tmp_path, [F()]))
    assert any(h.rule_id == "SEC-001" for h in hits) and warns == []


def test_sample_repo_cli_fixture(monkeypatch):
    monkeypatch.setenv("FAIL_OSV", "1")
    root = Path(__file__).parent / "fixtures" / "deterministic" / "sample_repo"
    hits, warns = asyncio.run(run_deterministic(root))
    assert warns == ["osv_unavailable"]
    assert {"SEC-001", "SEC-003", "SEC-010", "CI-001", "CI-002", "CI-003", "CI-006", "CI-007", "CI-008"} <= ids(hits)
    assert "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" not in "".join(h.model_dump_json() for h in hits)
