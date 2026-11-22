import { useId, useState } from "react";
import type { AuditReport, Finding } from "../api/types";
import { AREA_LABEL, SEV_COLOR, permalink } from "../lib";
import { Markdown } from "./Markdown";
import { Chip, SevBadge } from "./ui";

function Snippet({ f }: { f: Finding }) {
  const lines = f.snippet.split("\n");
  const last = f.end_line ?? f.line;
  return (
    <pre className="overflow-x-auto rounded-lg border border-line bg-bg py-2 font-mono text-[12.5px] leading-[1.7]">
      {lines.map((ln, i) => {
        const n = f.line + i;
        const hit = n >= f.line && n <= Math.max(last, f.line) && (f.end_line !== null || i === 0);
        return (
          <div key={i} className={`flex px-3 ${hit ? "bg-sev-high/10" : ""}`} style={hit ? { boxShadow: `inset 2px 0 0 ${SEV_COLOR[f.severity]}` } : undefined}>
            <span className="mr-4 w-10 shrink-0 select-none text-right text-faint">{n}</span>
            <code className="whitespace-pre">{ln || " "}</code>
          </div>
        );
      })}
    </pre>
  );
}

export function FindingRow({
  f,
  repo,
  selected,
  selectDisabled,
  onToggle,
  defaultOpen = false,
}: {
  f: Finding;
  repo: AuditReport["repo"];
  selected: boolean;
  selectDisabled: boolean;
  onToggle: (id: string) => void;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = f.area === "meta";
  const panelId = useId();
  return (
    <div
      className={`card overflow-hidden ${meta ? "border-sev-critical/50 bg-[repeating-linear-gradient(135deg,rgba(255,93,108,0.05)_0_10px,transparent_10px_20px)]" : ""}`}
      style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity]}` }}
    >
      <div className="flex items-start gap-3 px-4 py-3">
        <input
          type="checkbox"
          checked={selected}
          disabled={selectDisabled && !selected}
          onChange={() => onToggle(f.id)}
          aria-label={`Select "${f.title}" for issue draft`}
          className="mt-1.5 h-4 w-4 shrink-0 accent-[var(--color-accent)]"
        />
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          aria-controls={panelId}
          className="min-w-0 flex-1 text-left"
        >
          <div className="flex flex-wrap items-center gap-2">
            <SevBadge severity={f.severity} />
            {meta ? <Chip tone="danger">Attack in repo</Chip> : <Chip>{AREA_LABEL[f.area]}</Chip>}
            <Chip tone={f.source === "rule+agent" ? "accent" : "neutral"}>{f.source}</Chip>
          </div>
          <div className="mt-1.5 font-medium text-ink">{f.title}</div>
          <div className="mt-0.5 break-all font-mono text-[12px] text-muted">
            {f.file}:{f.line}
          </div>
        </button>
        <span aria-hidden="true" className={`mt-1.5 text-faint transition ${open ? "rotate-90" : ""}`}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M9 6l6 6-6 6" />
          </svg>
        </span>
      </div>
      {open && (
        <div id={panelId} className="space-y-4 border-t border-line px-4 py-4 pl-11">
          <Snippet f={f} />
          <p className="max-w-prose whitespace-pre-wrap text-[14.5px] text-ink/90">{f.explanation}</p>
          {f.agent_note && (
            <p className="max-w-prose rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-[13.5px] text-muted">
              <span className="font-semibold text-accent">Agent note.</span> {f.agent_note}
            </p>
          )}
          <div>
            <div className="mb-1.5 text-[13px] font-semibold text-muted">Suggested fix</div>
            <Markdown source={f.suggested_fix} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
            {f.cwe && <Chip>{f.cwe}</Chip>}
            {f.rule_ids.map((r) => (
              <Chip key={r}>
                <span className="font-mono">{r}</span>
              </Chip>
            ))}
            <Chip title="Model confidence">confidence {Math.round(f.confidence * 100)}%</Chip>
            <a
              href={permalink(repo.owner, repo.name, repo.commit, f.file, f.line)}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-auto text-accent underline-offset-4 hover:underline"
            >
              View on GitHub
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
