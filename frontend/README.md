# RepoGuard frontend

Single-page React + TypeScript (strict) + Tailwind v4 app. No router, no auth.
Flow: URL input -> live progress (SSE) -> report -> dry-run issue drafts.

## Run

```bash
# backend (mock data, no LLM/network)
cd .. && MOCK_MODE=1 uv run uvicorn backend.app.main:app --port 8000

# frontend
cd frontend && npm install && npm run dev      # http://localhost:5173
npm run typecheck && npm run build
```

## Config

- `VITE_API_BASE` API origin, default `http://localhost:8000`.
- `VITE_USE_LOCAL_MOCK=1` runs without a backend, using `src/mock/` (fixture report plus a simulated event stream).
  Example: `VITE_USE_LOCAL_MOCK=1 npm run dev`.

## Mock URLs (when `/api/health` reports `mock: true`)

`https://github.com/<o>/<r>/mock/not-found`, `/mock/degraded`, `/mock/slow`. Any valid GitHub URL gives the default report.

## Layout

`src/api/{types,client,sse}.ts` mirror `implementation.md` section 2. `src/components/` holds Landing, Progress, ReportView, FindingRow, Drafts and the small safe Markdown renderer (finding text is always rendered as text).
A running audit is kept in the URL hash (`#job=<id>`), so a refresh replays the event stream.
