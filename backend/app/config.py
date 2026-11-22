from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def parse_env_file(path: Path) -> dict[str, str]:
    """Tolerant .env parser: allows spaces around '=', quotes, 'export ' prefix, comments."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        if key:
            out[key] = value.strip()
    return out


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = field(default="", repr=False)
    model_id: str = "gemini-3.6-flash"
    mock_mode: bool = False
    max_concurrent_agents: int = 2


def get_settings() -> Settings:
    """Process env wins over .env file. Re-read on each call (cheap; keeps tests simple)."""
    file_vars: dict[str, str] = {}
    for p in (ROOT / ".env", Path.cwd() / ".env"):
        file_vars.update(parse_env_file(p))

    def get(name: str) -> str | None:
        v = os.environ.get(name)
        return v if v not in (None, "") else (file_vars.get(name) or None)

    key = (get("GEMINI_API_KEY") or get("GOOGLE_API_KEY") or "").strip()
    try:
        conc = max(1, int(get("MAX_CONCURRENT_AGENTS") or 2))
    except ValueError:
        conc = 2
    return Settings(
        gemini_api_key=key,
        model_id=get("MODEL_ID") or "gemini-3.6-flash",
        mock_mode=_truthy(get("MOCK_MODE")),
        max_concurrent_agents=conc,
    )
