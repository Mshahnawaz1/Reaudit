import { useMemo, useState } from "react";
import { createDrafts } from "../api/client";
import type { Area, AuditReport, Finding, Severity } from "../api/types";
import { AREA_LABEL, SEVERITIES, SEV_COLOR, SEV_RANK, STAGE_LABEL, scoreColor } from "../lib";
import { DraftFlow } from "./Drafts";
import { FindingRow } from "./FindingRow";
import { Chip, btnGhost, btnPrimary } from "./ui";

const MAX_SELECT = 10;

function ScoreRing({ score }: { score: number }) {
  const r = 44;
  const c = 2 * Math.PI * r;
  const color = scoreColor(score);
  return (
    <div className="relative h-[112px] w-[112px] shrink-0" role="img" aria-label={`Score ${score} out of 100`}>
      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--color-line)" strokeWidth="6" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" strokeDasharray={`${(c * score) / 100} ${c}`} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display text-[34px] font-bold leading-none" style={{ color }}>
          {score}
        </span>
        <span className="mt-0.5 text-[11px] text-faint">of 100</span>
      </div>
    </div>
  );
}

function Header({ report }: { report: AuditReport }) {
  const { repo, coverage: cv } = report;
  const degraded = report.stages.filter((s) => s.state === "degraded" || s.state === "failed");
  const capped = cv.caps_hit.length > 0;
  return (
    <div className="space-y-4">
      {degraded.length > 0 && (
        <div role="status" className="rounded-xl border border-sev-medium/40 bg-sev-medium/10 px-4 py-3 text-[14px] text-sev-medium">
          <strong className="font-semibold">Partial results.</strong>{" "}
          {degraded.map((s) => `${STAGE_LABEL[s.id]} ${s.state}${s.message ? ` (${s.message})` : ""}`).join("; ")}. Findings from these stages may be missing.
        </div>
      )}
      <div className="card flex flex-col gap-6 p-6 sm:flex-row sm:items-center">
        <ScoreRing score={report.score} />
        <div className="min-w-0 flex-1">
          <h1 className="break-words font-display text-[28px] font-bold leading-tight tracking-tight sm:text-[34px]">
            {repo.owner}/{repo.name}
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-muted">
            <span className="font-mono">{repo.commit.slice(0, 7)}</span>
            <span>branch {repo.branch}</span>
            <span>{new Date(report.generated_at).toLocaleString()}</span>
          </div>
          <p className="mt-3 max-w-prose text-[14.5px] text-ink/90">{report.summary}</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {SEVERITIES.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1 text-[13px]">
                <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
                <span className="font-semibold">{report.counts[s]}</span>
                <span className="capitalize text-muted">{s}</span>
              </span>
            ))}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <Chip title={Object.entries(cv.skipped_reasons).map(([k, v]) => `${k}: ${v}`).join(", ") || "Nothing skipped"}>
          Scanned {cv.files_scanned} of {cv.files_total} files
          {cv.files_skipped > 0 ? ` (${cv.files_skipped} skipped)` : ""}
        </Chip>
        {cv.languages.length > 0 && <Chip>{cv.languages.join(", ")}</Chip>}
        {report.dropped_unverified > 0 && (
          <Chip tone="accent" title="Findings the verify step could not tie to a real file, line and snippet">
            {report.dropped_unverified} unverified {report.dropped_unverified === 1 ? "finding" : "findings"} discarded
          </Chip>
        )}
        {capped && <Chip tone="warn">Scan limits reached: {cv.caps_hit.join(", ")}</Chip>}
      </div>
      {cv.reduced_coverage_languages.length > 0 && (
        <p className="text-[13.5px] text-sev-medium">
          Reduced coverage for {cv.reduced_coverage_languages.join(", ")}: only a secrets scan ran on these files.
        </p>
      )}
    </div>
  );
}

function TopFive({ ids, byId, repo, ...sel }: { ids: string[]; byId: Map<string, Finding>; repo: AuditReport["repo"]; selected: Set<string>; onToggle: (id: string) => void }) {
  const items = ids.map((id) => byId.get(id)).filter((f): f is Finding => f !== undefined);
  if (items.length === 0) return null;
  return (
    <section aria-labelledby="top5">
      <h2 id="top5" className="mb-3 font-display text-[22px] font-bold tracking-tight">
        Fix these first
      </h2>
      <ol className="space-y-3">
        {items.map((f, i) => (
          <li key={f.id} className="flex items-start gap-3">
            <span className="mt-3.5 w-5 shrink-0 text-right font-display text-[18px] font-bold text-faint">{i + 1}</span>
            <div className="min-w-0 flex-1">
              <FindingRow f={f} repo={repo} selected={sel.selected.has(f.id)} selectDisabled={sel.selected.size >= MAX_SELECT} onToggle={sel.onToggle} />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function ReportView({ report, onNew }: { report: AuditReport; onNew: () => void }) {
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [areaFilter, setAreaFilter] = useState<Set<Area>>(new Set());
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [drafting, setDrafting] = useState(false);

  const byId = useMemo(() => new Map(report.findings.map((f) => [f.id, f])), [report.findings]);
  const areas = useMemo(() => [...new Set(report.findings.map((f) => f.area))], [report.findings]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return report.findings
      .filter((f) => sevFilter.size === 0 || sevFilter.has(f.severity))
      .filter((f) => areaFilter.size === 0 || areaFilter.has(f.area))
      .filter((f) => !q || [f.title, f.file, f.explanation, f.cwe ?? "", ...f.rule_ids].join(" ").toLowerCase().includes(q))
      .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  }, [report.findings, sevFilter, areaFilter, query]);

  function toggle<T>(set: Set<T>, v: T): Set<T> {
    const n = new Set(set);
    if (n.has(v)) n.delete(v);
    else n.add(v);
    return n;
  }
  const onToggle = (id: string) =>
    setSelected((s) => {
      if (!s.has(id) && s.size >= MAX_SELECT) return s;
      return toggle(s, id);
    });

  const selectedIds = [...selected];
  const empty = report.findings.length === 0;
  const pill = (active: boolean) =>
    `rounded-full border px-3 py-1 text-[13px] transition ${active ? "border-accent bg-accent/15 text-ink" : "border-line-strong text-muted hover:text-ink"}`;

  return (
    <div className="mt-6 space-y-10">
      <div className="flex justify-end">
        <button className={btnGhost} onClick={onNew}>
          Audit another repo
        </button>
      </div>
      <Header report={report} />

      {empty ? (
        <div className="card p-10 text-center">
          <h2 className="font-display text-[24px] font-bold tracking-tight">No issues found in scanned scope</h2>
          <p className="mx-auto mt-2 max-w-md text-muted">
            This is not a guarantee of security. Review the coverage above to see what was and was not scanned.
          </p>
        </div>
      ) : (
        <>
          <TopFive ids={report.top5} byId={byId} repo={report.repo} selected={selected} onToggle={onToggle} />

          <section aria-labelledby="all">
            <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
              <h2 id="all" className="font-display text-[22px] font-bold tracking-tight">
                All findings <span className="text-faint">{visible.length}</span>
              </h2>
              <label className="w-full sm:w-72">
                <span className="sr-only">Search findings</span>
                <input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search title, file, rule, CWE"
                  className="w-full rounded-lg border border-line-strong bg-surface px-3 py-2 text-[14px] outline-none placeholder:text-faint focus:border-accent"
                />
              </label>
            </div>
            <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Filter by severity">
              {SEVERITIES.filter((s) => report.counts[s] > 0).map((s) => (
                <button key={s} aria-pressed={sevFilter.has(s)} className={`${pill(sevFilter.has(s))} capitalize`} onClick={() => setSevFilter((p) => toggle(p, s))}>
                  <span className="mr-1.5 inline-block h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
                  {s} {report.counts[s]}
                </button>
              ))}
              <span className="mx-1 w-px bg-line" aria-hidden="true" />
              {areas.map((a) => (
                <button key={a} aria-pressed={areaFilter.has(a)} className={pill(areaFilter.has(a))} onClick={() => setAreaFilter((p) => toggle(p, a))}>
                  {AREA_LABEL[a]}
                </button>
              ))}
            </div>
            {visible.length === 0 ? (
              <p className="card p-6 text-center text-muted">No findings match these filters.</p>
            ) : (
              <div className="space-y-3">
                {visible.map((f) => (
                  <FindingRow key={f.id} f={f} repo={report.repo} selected={selected.has(f.id)} selectDisabled={selected.size >= MAX_SELECT} onToggle={onToggle} />
                ))}
              </div>
            )}
          </section>
        </>
      )}

      {report.dismissed.length > 0 && (
        <details className="card group">
          <summary className="cursor-pointer list-none px-5 py-4 font-medium">
            Dismissed by agents <span className="text-faint">{report.dismissed.length}</span>
            <span className="ml-2 text-[13px] font-normal text-muted">Rule hits the agents judged to be false positives</span>
          </summary>
          <ul className="divide-y divide-line border-t border-line">
            {report.dismissed.map((d, i) => (
              <li key={i} className="px-5 py-3 text-[14px]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[12px] text-accent">{d.rule_id}</span>
                  <span className="break-all font-mono text-[12px] text-muted">
                    {d.file}:{d.line}
                  </span>
                </div>
                <p className="mt-1 text-muted">{d.reason}</p>
              </li>
            ))}
          </ul>
        </details>
      )}

      {selected.size > 0 && (
        <div className="fixed inset-x-0 bottom-0 z-40 border-t border-line-strong bg-surface/95 backdrop-blur">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-5 py-3">
            <span className="text-[14px]">
              {selected.size} of {MAX_SELECT} selected
            </span>
            <button className="text-[13px] text-muted underline-offset-4 hover:underline" onClick={() => setSelected(new Set())}>
              Clear
            </button>
            <button className={`${btnPrimary} ml-auto`} onClick={() => setDrafting(true)}>
              Draft issues
            </button>
          </div>
        </div>
      )}

      {drafting && (
        <DraftFlow
          count={selectedIds.length}
          titles={selectedIds.map((id) => byId.get(id)?.title ?? id)}
          onClose={() => setDrafting(false)}
          onCreate={async () => (await createDrafts(report.job_id, selectedIds)).drafts}
        />
      )}
    </div>
  );
}
