import { useEffect, useReducer, useRef, useState } from "react";
import { ApiRequestError, getReport } from "../api/client";
import { subscribeToJob } from "../api/sse";
import type { Area, AuditReport, ErrorCode, StageId, StageState } from "../api/types";
import { AREA_LABEL, STAGE_LABEL, STAGE_ORDER } from "../lib";
import { Chip, StageIcon, Spinner, btnGhost, btnPrimary } from "./ui";

interface StageView {
  state: StageState;
  message: string | null;
}
interface PState {
  stages: Record<StageId, StageView>;
  hits: { by_area: Partial<Record<Area, number>>; total: number } | null;
  log: { key: string; stage: StageId; message: string }[];
  warnings: { key: string; code: string; message: string }[];
  fatal: { code: ErrorCode | "connection_lost" | "network_error"; message: string } | null;
  done: boolean;
}
type Action =
  | { type: "stage"; stage: StageId; state: StageState; message?: string }
  | { type: "hits"; by_area: Partial<Record<Area, number>>; total: number }
  | { type: "log"; key: string; stage: StageId; message: string }
  | { type: "warning"; key: string; code: string; message: string }
  | { type: "fatal"; code: NonNullable<PState["fatal"]>["code"]; message: string }
  | { type: "done" }
  | { type: "reset" };

function initial(): PState {
  const stages = {} as Record<StageId, StageView>;
  for (const id of STAGE_ORDER) stages[id] = { state: "pending", message: null };
  return { stages, hits: null, log: [], warnings: [], fatal: null, done: false };
}

function reducer(s: PState, a: Action): PState {
  switch (a.type) {
    case "stage":
      return { ...s, stages: { ...s.stages, [a.stage]: { state: a.state, message: a.message ?? null } } };
    case "hits":
      return { ...s, hits: { by_area: a.by_area, total: a.total } };
    case "log":
      return s.log.some((l) => l.key === a.key) ? s : { ...s, log: [...s.log, { key: a.key, stage: a.stage, message: a.message }].slice(-40) };
    case "warning":
      return s.warnings.some((w) => w.key === a.key) ? s : { ...s, warnings: [...s.warnings, { key: a.key, code: a.code, message: a.message }] };
    case "fatal":
      return { ...s, fatal: { code: a.code, message: a.message } };
    case "done":
      return { ...s, done: true };
    case "reset":
      return initial();
  }
}

const FATAL_HINT: Partial<Record<string, string>> = {
  repo_not_found: "Check the spelling and that the repository is public.",
  repo_private_or_forbidden: "RepoGuard only audits public repositories.",
  repo_too_large: "The repository exceeds the size limit. Try a smaller one.",
  repo_empty: "The repository has no files to scan.",
  clone_timeout: "Fetching took too long. Try again in a moment.",
  rate_limited: "Too many requests. Wait a little, then retry.",
  llm_unavailable: "The analysis model is unavailable right now.",
  job_not_found: "This audit no longer exists. Start a new one.",
};

export function Progress({
  jobId,
  onReport,
  onRetry,
}: {
  jobId: string;
  onReport: (r: AuditReport) => void;
  onRetry: () => void;
}) {
  const [s, dispatch] = useReducer(reducer, undefined, initial);
  const [attempt, setAttempt] = useState(0);
  const [startedAt] = useState(() => Date.now());
  const [elapsed, setElapsed] = useState(0);
  const onReportRef = useRef(onReport);
  onReportRef.current = onReport;

  useEffect(() => {
    dispatch({ type: "reset" });
    let alive = true;
    const unsub = subscribeToJob(jobId, {
      stage: (e) => dispatch({ type: "stage", stage: e.stage, state: e.state, ...(e.message ? { message: e.message } : {}) }),
      hits: (e) => dispatch({ type: "hits", by_area: e.by_area, total: e.total }),
      agent_progress: (e) => dispatch({ type: "log", key: `${e.ts}|${e.stage}|${e.message}`, stage: e.stage, message: e.message }),
      warning: (e) => dispatch({ type: "warning", key: `${e.ts}|${e.code}`, code: e.code, message: e.message }),
      error: (e) => dispatch({ type: "fatal", code: e.code, message: e.message }),
      onConnectionLost: () => dispatch({ type: "fatal", code: "connection_lost", message: "Lost connection to the audit stream." }),
      done: () => {
        dispatch({ type: "done" });
        getReport(jobId)
          .then((r) => alive && onReportRef.current(r))
          .catch((err: unknown) => {
            if (!alive) return;
            const msg = err instanceof ApiRequestError ? err.message : "Could not load the report.";
            dispatch({ type: "fatal", code: err instanceof ApiRequestError && err.code === "network_error" ? "network_error" : "internal_error", message: msg });
          });
      },
    });
    return () => {
      alive = false;
      unsub();
    };
  }, [jobId, attempt]);

  useEffect(() => {
    if (s.fatal) return;
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000);
    return () => clearInterval(t);
  }, [s.fatal, startedAt]);

  if (s.fatal) {
    const hint = FATAL_HINT[s.fatal.code];
    const canResume = s.fatal.code === "connection_lost" || s.fatal.code === "network_error" || s.fatal.code === "internal_error";
    return (
      <section className="mx-auto mt-20 max-w-xl">
        <div role="alert" className="card border-sev-critical/40 p-6">
          <h1 className="font-display text-[24px] font-bold tracking-tight">The audit could not finish</h1>
          <p className="mt-3 text-ink/90">{s.fatal.message}</p>
          {hint && <p className="mt-1 text-[14px] text-muted">{hint}</p>}
          <p className="mt-4 font-mono text-[12px] text-faint">code: {s.fatal.code}</p>
          <div className="mt-6 flex flex-wrap gap-3">
            {canResume && (
              <button className={btnPrimary} onClick={() => setAttempt((n) => n + 1)}>
                Retry
              </button>
            )}
            <button className={canResume ? btnGhost : btnPrimary} onClick={onRetry}>
              Start a new audit
            </button>
          </div>
        </div>
      </section>
    );
  }

  const running = STAGE_ORDER.find((id) => s.stages[id].state === "running");
  return (
    <section className="mx-auto mt-14 max-w-3xl">
      <div className="mb-8 text-center">
        <h1 className="font-display text-[34px] font-bold tracking-tight sm:text-[44px]">
          {s.done ? "Building your report" : "Auditing the repository"}
        </h1>
        <p className="mt-2 text-muted">
          {running ? STAGE_LABEL[running] : "Starting up"} <span className="font-mono text-[13px] text-faint">{elapsed}s</span>
        </p>
        <div className="scanline mx-auto mt-5 h-[3px] max-w-xs rounded-full bg-line" aria-hidden="true" />
      </div>

      {s.warnings.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2" aria-live="polite">
          {s.warnings.map((w) => (
            <Chip key={w.key} tone="warn" title={w.code}>
              {w.message}
            </Chip>
          ))}
        </div>
      )}

      <div className="card divide-y divide-line">
        {STAGE_ORDER.map((id) => {
          const st = s.stages[id];
          return (
            <div key={id} className="flex items-start gap-3 px-5 py-3.5">
              <div className="mt-0.5 shrink-0">
                <StageIcon state={st.state} />
              </div>
              <div className="min-w-0 flex-1">
                <div className={`font-medium ${st.state === "pending" ? "text-faint" : "text-ink"}`}>{STAGE_LABEL[id]}</div>
                {st.message && <div className="text-[13px] text-muted">{st.message}</div>}
                {id === "deterministic" && s.hits && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Chip tone="accent">{s.hits.total} candidate hits</Chip>
                    {(Object.entries(s.hits.by_area) as [Area, number][]).map(([area, n]) => (
                      <Chip key={area}>
                        {AREA_LABEL[area]} {n}
                      </Chip>
                    ))}
                  </div>
                )}
              </div>
              <span className="mt-0.5 text-[12px] text-faint">{st.state === "pending" ? "" : st.state}</span>
            </div>
          );
        })}
      </div>

      <div className="card mt-4 p-4" aria-live="polite">
        <div className="mb-2 flex items-center gap-2 text-[13px] text-muted">
          {!s.done && <Spinner size={14} />}
          Agent activity
        </div>
        {s.log.length === 0 ? (
          <p className="font-mono text-[12.5px] text-faint">Waiting for agents.</p>
        ) : (
          <ul className="max-h-48 space-y-1 overflow-y-auto font-mono text-[12.5px] text-muted">
            {s.log.map((l) => (
              <li key={l.key}>
                <span className="text-faint">{STAGE_LABEL[l.stage]}</span> {l.message}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
