"""Gemini-through-Agno runner: structured output, timeouts, 429 backoff, repair retry, concurrency cap."""
from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any, Awaitable, Callable, TypeVar

from pydantic import BaseModel, ValidationError

from backend.app.agents.types import AgentResult, NewFinding, Verdict, hit_key
from backend.app.config import get_settings

T = TypeVar("T", bound=BaseModel)

_BACKOFF_BASE = 2.0
_MAX_RATE_RETRIES = 3
_semaphores: dict[tuple[int, int], asyncio.Semaphore] = {}


class AgentError(Exception):
    """code: agent_timeout | llm_unavailable | schema_invalid | internal_error"""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class SchemaError(Exception):
    pass


class AgentOutput(BaseModel):
    verdicts: list[Verdict] = []
    new_findings: list[NewFinding] = []
    notes: str | None = None


def _semaphore() -> asyncio.Semaphore:
    n = get_settings().max_concurrent_agents
    key = (id(asyncio.get_running_loop()), n)
    if key not in _semaphores:
        _semaphores[key] = asyncio.Semaphore(n)
    return _semaphores[key]


def _scrub(text: str) -> str:
    key = get_settings().gemini_api_key
    if key:
        text = text.replace(key, "***")
    return text[:200]


def _is_rate_limit(e: Exception) -> bool:
    s = f"{type(e).__name__} {e}"
    return "429" in s or "RESOURCE_EXHAUSTED" in s or "rate limit" in s.lower()


def _coerce(content: Any, model: type[T]) -> T:
    if isinstance(content, model):
        return content
    try:
        if isinstance(content, BaseModel):
            return model.model_validate(content.model_dump())
        if isinstance(content, dict):
            return model.model_validate(content)
        if isinstance(content, str):
            text = content.strip()
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
            return model.model_validate_json(text)
    except (ValidationError, json.JSONDecodeError, ValueError) as e:
        raise SchemaError(str(e)[:300]) from e
    raise SchemaError(f"unexpected output type {type(content).__name__}")


async def _invoke(*, instructions: str, prompt: str, output_model: type[BaseModel], tools: list | None, timeout: float) -> Any:
    from agno.agent import Agent
    from agno.models.google import Gemini

    s = get_settings()
    model = Gemini(id=s.model_id, api_key=s.gemini_api_key, thinking_budget=0)
    agent = Agent(
        model=model, instructions=instructions, tools=tools or None, output_schema=output_model,
        tool_call_limit=14 if tools else None, markdown=False,
    )
    result = await asyncio.wait_for(agent.arun(prompt), timeout=timeout)
    return result.content


async def run_structured(
    *, instructions: str, prompt: str, output_model: type[T], tools: list | None = None,
    timeout: float = 45, retries: int = 1,
) -> T:
    if os.environ.get("FAIL_LLM") == "1":
        raise AgentError("llm_unavailable", "FAIL_LLM=1 simulated outage")
    if not get_settings().gemini_api_key:
        raise AgentError("llm_unavailable", "no API key configured")
    async with _semaphore():
        attempt = 0
        rate_hits = 0
        cur_prompt = prompt
        while True:
            try:
                content = await _invoke(
                    instructions=instructions, prompt=cur_prompt, output_model=output_model,
                    tools=tools, timeout=timeout,
                )
                return _coerce(content, output_model)
            except asyncio.TimeoutError:
                if attempt >= retries:
                    raise AgentError("agent_timeout", f"no response within {timeout}s") from None
                attempt += 1
            except SchemaError as e:
                if attempt >= retries:
                    raise AgentError("schema_invalid", _scrub(str(e))) from None
                attempt += 1
                cur_prompt = (
                    prompt + "\n\nYour previous reply did not match the required JSON schema "
                    f"({_scrub(str(e))}). Reply again with ONLY valid JSON matching the schema."
                )
            except AgentError:
                raise
            except Exception as e:  # provider/network errors
                if _is_rate_limit(e) and rate_hits < _MAX_RATE_RETRIES:
                    rate_hits += 1
                    await asyncio.sleep(_BACKOFF_BASE * 2 ** (rate_hits - 1))
                    continue
                if not _is_rate_limit(e) and attempt < retries and not re.search(r"40[0134]|API key|PERMISSION", str(e)):
                    attempt += 1
                    await asyncio.sleep(1.0)
                    continue
                raise AgentError("llm_unavailable", _scrub(f"{type(e).__name__}: {e}")) from None


async def run_agent_safely(name: str, coro_factory: Callable[[], Awaitable[AgentResult]]) -> AgentResult:
    """Never raises (except cancellation): any failure becomes a degraded/failed AgentResult."""
    try:
        return await coro_factory()
    except AgentError as e:
        status = "failed" if e.code == "llm_unavailable" else "degraded"
        return AgentResult(agent=name, status=status, warning=e.code, notes=_scrub(e.detail) or None)  # type: ignore[arg-type]
    except asyncio.CancelledError:
        raise
    except Exception as e:
        return AgentResult(agent=name, status="failed", warning="internal_error", notes=_scrub(type(e).__name__))  # type: ignore[arg-type]


def complete_verdicts(hits: list, verdicts: list[Verdict]) -> list[Verdict]:
    """Exactly one verdict per incoming hit; unknown keys dropped; missing ones default to confirm."""
    by_key: dict[str, Verdict] = {}
    valid = {hit_key(h) for h in hits}
    for v in verdicts:
        if v.hit_key in valid and v.hit_key not in by_key:
            by_key[v.hit_key] = v
    out = []
    seen: set[str] = set()
    for h in hits:
        k = hit_key(h)
        if k in seen:
            continue
        seen.add(k)
        out.append(by_key.get(k) or Verdict(hit_key=k, decision="confirm", reason="not reviewed by agent"))
    return out
