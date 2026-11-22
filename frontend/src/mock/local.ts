import type { AuditReport, HealthResponse, IssueDraftsResponse, StartAuditResponse } from "../api/types";
import type { SseHandlers } from "../api/sse";
import { fixtureReport } from "./fixture";

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const jobs = new Map<string, string>();
const ts = () => new Date().toISOString();

type Step = { delay: number; run: (h: SseHandlers, url: string) => void };

const steps: Step[] = [
  { delay: 300, run: (h) => h.stage?.({ ts: ts(), stage: "ingest", state: "running" }) },
  { delay: 900, run: (h) => h.stage?.({ ts: ts(), stage: "ingest", state: "done" }) },
  { delay: 200, run: (h) => h.stage?.({ ts: ts(), stage: "deterministic", state: "running" }) },
  { delay: 900, run: (h) => h.hits?.({ ts: ts(), stage: "deterministic", by_area: { secrets: 5, deps: 12, ci: 7 }, total: 24 }) },
  { delay: 300, run: (h) => h.stage?.({ ts: ts(), stage: "deterministic", state: "done" }) },
  { delay: 300, run: (h) => { h.stage?.({ ts: ts(), stage: "ci_agent", state: "running" }); h.stage?.({ ts: ts(), stage: "secrets_agent", state: "running" }); } },
  { delay: 800, run: (h) => h.agent_progress?.({ ts: ts(), stage: "ci_agent", message: "Reading .github/workflows/ci.yml" }) },
  { delay: 800, run: (h) => h.agent_progress?.({ ts: ts(), stage: "secrets_agent", message: "Reviewing 5 candidate secrets" }) },
  { delay: 700, run: (h, url) => { if (url.includes("degraded")) h.warning?.({ ts: ts(), stage: "deterministic", code: "osv_unavailable", message: "Dependency database unreachable; dependency results are incomplete." }); } },
  { delay: 900, run: (h) => { h.stage?.({ ts: ts(), stage: "ci_agent", state: "done" }); h.stage?.({ ts: ts(), stage: "secrets_agent", state: "done" }); h.stage?.({ ts: ts(), stage: "code_agent", state: "running" }); } },
  { delay: 900, run: (h) => h.agent_progress?.({ ts: ts(), stage: "code_agent", message: "Reading app/routes/search.py" }) },
  { delay: 900, run: (h) => h.stage?.({ ts: ts(), stage: "code_agent", state: "degraded", message: "Timed out; partial results" }) },
  { delay: 400, run: (h) => { h.stage?.({ ts: ts(), stage: "verify", state: "running" }); } },
  { delay: 500, run: (h) => { h.stage?.({ ts: ts(), stage: "verify", state: "done" }); h.stage?.({ ts: ts(), stage: "synthesize", state: "running" }); } },
  { delay: 700, run: (h) => { h.stage?.({ ts: ts(), stage: "synthesize", state: "done" }); h.done?.({ ts: ts(), job_id: "local-mock", score: fixtureReport.score }); } },
];

export const localMock = {
  async getHealth(): Promise<HealthResponse> {
    await wait(100);
    return { status: "ok", mock: true, model: "local-fixture" };
  },
  async startAudit(url: string): Promise<StartAuditResponse> {
    await wait(200);
    const id = `local-mock-${jobs.size + 1}`;
    jobs.set(id, url);
    return { job_id: id };
  },
  async getReport(_jobId?: string): Promise<AuditReport> {
    await wait(200);
    return fixtureReport;
  },
  async createDrafts(_jobId: string, ids: string[]): Promise<IssueDraftsResponse> {
    await wait(300);
    return {
      drafts: ids.map((id) => {
        const f = fixtureReport.findings.find((x) => x.id === id);
        return {
          finding_id: id,
          title: `[${f?.severity ?? "info"}] ${f?.title ?? id}`,
          labels: ["security", f?.severity ?? "info"],
          body_markdown: `**${f?.title ?? id}**\n\n${f?.explanation ?? ""}\n\n\`${f?.file ?? ""}:${f?.line ?? 0}\`\n\n### Suggested fix\n${f?.suggested_fix ?? ""}`,
        };
      }),
    };
  },
  subscribe(jobId: string, h: SseHandlers): () => void {
    const url = jobs.get(jobId) ?? "";
    if (url.includes("not-found")) {
      const t = setTimeout(() => h.error?.({ ts: ts(), code: "repo_not_found", message: "Repository not found or not public." }), 800);
      return () => clearTimeout(t);
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let i = 0;
    const next = () => {
      const s = steps[i];
      if (cancelled || !s) return;
      timer = setTimeout(() => {
        if (cancelled) return;
        s.run(h, url);
        i += 1;
        next();
      }, s.delay);
    };
    next();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  },
};
