from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from . import pipeline
from .config import get_settings
from .drafts import build_drafts
from .errors import install_handlers
from .ingest import parse_repo_url
from .jobs import store
from .mock.replay import run_mock, split_mock_url
from .models import (
    AuditAccepted, AuditReport, AuditRequest, Health, IssueDraftsRequest, IssueDraftsResponse,
)

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="RepoGuard", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
install_handlers(app)


@app.get("/api/health", response_model=Health)
async def health() -> Health:
    s = get_settings()
    return Health(mock=s.mock_mode, model=s.model_id)


@app.post("/api/audit", status_code=202, response_model=AuditAccepted)
async def start_audit(body: AuditRequest) -> AuditAccepted:
    settings = get_settings()
    url, kind = split_mock_url(body.repo_url) if settings.mock_mode else (body.repo_url, None)
    ref = parse_repo_url(url)
    job = store.create(ref.canonical_url)
    if settings.mock_mode:
        job.task = asyncio.create_task(run_mock(job, ref, kind))
    else:
        job.task = asyncio.create_task(pipeline.run_pipeline(job, ref))
    return AuditAccepted(job_id=job.id)


@app.get("/api/audit/{job_id}/events")
async def audit_events(job_id: str) -> EventSourceResponse:
    job = store.get(job_id)

    async def gen() -> AsyncIterator[dict[str, Any]]:
        async for event, data in job.subscribe():
            yield {"event": event, "data": json.dumps(data)}

    return EventSourceResponse(gen(), ping=15, headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/audit/{job_id}", response_model=AuditReport)
async def get_report(job_id: str) -> AuditReport:
    job = store.get_ready(job_id)
    assert job.report is not None
    return job.report


@app.post("/api/audit/{job_id}/issue-drafts", response_model=IssueDraftsResponse)
async def issue_drafts(job_id: str, body: IssueDraftsRequest) -> IssueDraftsResponse:
    job = store.get_ready(job_id)
    assert job.report is not None
    return IssueDraftsResponse(drafts=build_drafts(job.report, body.finding_ids))
