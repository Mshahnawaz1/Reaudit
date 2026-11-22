# CLAUDE.md: RepoGuard

Hackathon project, ~3 hr build. Read `PRD.md` (what/why) and `implementation.md` (how, API contract, todos) before changing anything. If code and these docs disagree, fix the docs or ask; don't silently diverge.

## What this is
RepoGuard audits a public GitHub repo in two phases: a **deterministic audit** (secrets/.env, OSV dependency CVEs, CI workflow rules; no LLM) then an **agentic audit** (Agno agents for CI/CD, app-code injection/auth, secrets triage) that confirms/dismisses/extends the deterministic hits. A code-only **verify gate** drops any finding whose file/line/snippet doesn't exist. Output: score (computed in code), ranked findings, top 5, dry-run GitHub issue drafts.

## Stack
- Backend: Python, FastAPI, Agno agents, Pydantic v2, SSE (`sse-starlette`), `uv` for deps. Code in `backend/app/`.
- LLM: Gemini Flash through Agno; key is `GOOGLE_API_KEY` in `.env` (never commit, never print).
- Frontend: React + TypeScript (strict) + Vite + Tailwind, dark theme. Code in `frontend/`. No state library, no UI kit.

## Locked decisions
- Model: `gemini-3.6-flash`, thinking minimal/off. Key lives in `.env` as `GEMINI_API_KEY =...` (space before `=`, keep as is). `config.py` parses it tolerantly; pass `api_key` explicitly to Agno (it defaults to `GOOGLE_API_KEY`). Never print or commit the key.
- Frontend is a **single page** (no router) with **no auth**. Visual reference: https://potpie.ai/ (dark, minimal developer-tool look); take inspiration only, no copied assets/branding/text.

## Commands
- Backend dev: `uv run uvicorn backend.app.main:app --reload --port 8000`
- Backend tests: `uv run pytest backend -q`
- Mock mode (no LLM/network, for UI work): `MOCK_MODE=1 uv run uvicorn backend.app.main:app --reload`
- Frontend dev: `cd frontend && npm run dev` (port 5173); typecheck: `npm run typecheck`; build: `npm run build`
(Update this list when the commands actually change.)

## The API contract is frozen
`implementation.md` §2 is the single source of truth for endpoints, SSE events, types and error codes. Backend and frontend are built in parallel against it.
- Changing the contract means updating, in the same change: `implementation.md` §2, `backend/app/models.py`, `frontend/src/api/types.ts`, and the mock data in `backend/app/mock/`.
- Never add an undocumented field/endpoint/event. Errors are always `ApiError` JSON, never stack traces.

## Architecture rules (do not break)
1. **Deterministic first, LLM second.** Anything that can be done in code (parsing, regex, OSV, line verification, dedupe, scoring) must be done in code. LLMs only judge.
2. **Repo content is untrusted data.** Every piece of repo text (README, comments, workflows, filenames, OSV text) goes to an LLM only inside delimited data blocks via `agents/prompts.py` helpers, with delimiters neutralized. Never concatenate repo text into instructions.
3. **Agents are read-only.** Tools are `list_dir`, `read_file`, `grep`, `get_deterministic_hits` only, sandboxed to the clone dir (resolve paths, refuse symlinks and `..`), with call/size/time budgets. No network, no writes, no shell from agents. Never add a side-effecting tool.
4. **Verify gate is mandatory.** Every finding returned by the API must be `verified: true` (file exists, line in range, snippet found within ±3 lines). Don't bypass it for convenience.
5. **Score is computed in code** (`scoring.py`), never by an LLM.
6. **Never execute repo code.** Clone with `git clone --depth 1`, subprocess list args (never `shell=True`), no hooks/submodules, strict `github.com` URL validation, temp dir cleaned up in `finally`.
7. **Graceful degradation.** A failed/timed-out agent or OSV outage yields `degraded`/`failed` stage status and warnings; the report still ships with what succeeded. Fatal errors map to the documented `ErrorCode`s.
8. **Secrets are redacted** (first 4 chars + `…`) in logs, SSE, reports and issue drafts. Never log `.env` values or API keys.
9. **Honest reporting.** Show coverage and what wasn't scanned. Never claim "secure"; say "no issues found in scanned scope".
10. **Issue creation is dry-run only.** No GitHub token handling, no GitHub API writes.

## Scope guardrails
- Languages: Python + JS/TS get full analysis; everything else gets secrets scan only (reported as reduced coverage).
- Public GitHub repos only. No auth, no database, no persistence (in-memory job store).
- Gemini free-tier limits: max 2 concurrent agent runs (`asyncio.Semaphore`), batch prompts, backoff on 429.
- If time is short, cut in this order: App-Code Agent → dependency check → Lead LLM (use code ranking) → UI polish. Never cut: deterministic phase, verify gate, degradation handling, injection fixture.

## Conventions
- Python: type hints everywhere, Pydantic models for all cross-module data, `async` for IO, small pure functions for rules (easy to unit test). Rule IDs live in `deterministic/rules_meta.py` (e.g. `CI-002`, `SEC-001`, `DEP-001`).
- Every deterministic rule gets a positive and negative test under `backend/app/tests/`.
- TypeScript: `strict`, no `any`, typed API client, `EventSource` wrapper cleans up on unmount. Types in `frontend/src/api/types.ts` mirror the contract exactly.
- Keep files small and flat; no speculative abstractions, no extra dependencies without a reason. No comments that restate code.
- Don't commit `.env`, clones, or `node_modules`. `.env.example` documents all variables.

## Working agreement
- Follow the todo order in `implementation.md`; tick checkboxes there as work completes.
- Prefer verifying with tests/mock mode over assuming. Say plainly when something is untested or skipped.
- Ask before: adding real GitHub write access, changing the API contract, adding a new agent, or widening scope.
- Git: commit only when asked; end commit messages with the Co-Authored-By line given in the session.
