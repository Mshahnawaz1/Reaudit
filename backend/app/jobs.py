from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

from .errors import AppError, make_error
from .models import AuditReport

TERMINAL = {"done", "error"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Job:
    def __init__(self, job_id: str, repo_url: str):
        self.id = job_id
        self.repo_url = repo_url
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.cond = asyncio.Condition()
        self.status: str = "running"  # running | done | failed
        self.report: AuditReport | None = None
        self.error: tuple[str, str] | None = None  # (code, message)
        self.task: asyncio.Task[None] | None = None

    async def emit(self, event: str, data: dict[str, Any]) -> None:
        payload = {"ts": now_iso(), **data}
        async with self.cond:
            if self.status != "running":
                return
            if event == "done":
                self.status = "done"
            elif event == "error":
                self.status = "failed"
                self.error = (str(data.get("code")), str(data.get("message")))
            self.events.append((event, payload))
            self.cond.notify_all()

    async def stage(self, stage: str, state: str, message: str | None = None) -> None:
        d: dict[str, Any] = {"stage": stage, "state": state}
        if message:
            d["message"] = message
        await self.emit("stage", d)

    async def warn(self, stage: str, code: str, message: str) -> None:
        await self.emit("warning", {"stage": stage, "code": code, "message": message})

    async def progress(self, stage: str, message: str) -> None:
        await self.emit("agent_progress", {"stage": stage, "message": message})

    async def fail(self, code: str, message: str) -> None:
        await self.emit("error", {"code": code, "message": message})

    async def subscribe(self) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """Replay from the start, then follow live; ends after done/error."""
        i = 0
        while True:
            async with self.cond:
                await self.cond.wait_for(lambda: len(self.events) > i)
                batch = self.events[i:]
            for ev in batch:
                i += 1
                yield ev
                if ev[0] in TERMINAL:
                    return


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def create(self, repo_url: str) -> Job:
        job = Job(uuid.uuid4().hex[:12], repo_url)
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise make_error("job_not_found", "Job not found")
        return job

    def get_ready(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job.status == "running":
            raise make_error("job_not_ready", "Audit is still running")
        if job.status == "failed":
            code, msg = job.error or ("internal_error", "Audit failed")
            raise AppError(code, msg, 422)  # type: ignore[arg-type]
        return job


store = JobStore()
