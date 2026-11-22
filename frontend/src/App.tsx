import { useCallback, useEffect, useRef, useState } from "react";
import type { AuditReport } from "./api/types";
import { Landing } from "./components/Landing";
import { Progress } from "./components/Progress";
import { ReportView } from "./components/ReportView";
import { Logo } from "./components/ui";

type View =
  | { kind: "input"; prefill: string; notice: string | null }
  | { kind: "progress"; jobId: string }
  | { kind: "report"; report: AuditReport };

function jobFromHash(): string | null {
  const m = /^#job=([\w-]+)$/.exec(window.location.hash);
  return m?.[1] ?? null;
}

export function App() {
  const [view, setView] = useState<View>(() => {
    const id = jobFromHash();
    return id ? { kind: "progress", jobId: id } : { kind: "input", prefill: "", notice: null };
  });

  const lastUrl = useRef("");

  const reset = useCallback((prefill = "", notice: string | null = null) => {
    history.replaceState(null, "", window.location.pathname);
    setView({ kind: "input", prefill, notice });
  }, []);

  const onStarted = useCallback((jobId: string, url: string) => {
    lastUrl.current = url;
    history.replaceState(null, "", `#job=${jobId}`);
    setView({ kind: "progress", jobId });
  }, []);

  useEffect(() => {
    document.title = view.kind === "report" ? `${view.report.repo.owner}/${view.report.repo.name} audit - RepoGuard` : "RepoGuard";
  }, [view]);

  return (
    <div className="relative min-h-screen overflow-x-hidden">
      <div className="hero-glow pointer-events-none absolute inset-x-0 top-0 h-[640px]" aria-hidden="true" />
      <div className="dot-grid pointer-events-none absolute inset-x-0 top-0 h-[640px]" aria-hidden="true" />
      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-5 py-5">
        <Logo onClick={() => reset()} />
        <span className="text-[13px] text-muted">Read-only audits of public GitHub repos</span>
      </header>
      <main className="relative z-10 mx-auto max-w-6xl px-5 pb-24">
        {view.kind === "input" && <Landing prefill={view.prefill} notice={view.notice} onStarted={onStarted} />}
        {view.kind === "progress" && (
          <Progress
            jobId={view.jobId}
            onReport={(report) => setView({ kind: "report", report })}
            onRetry={() => reset(lastUrl.current)}
          />
        )}
        {view.kind === "report" && <ReportView report={view.report} onNew={() => reset()} />}
      </main>
    </div>
  );
}
