import type { ReactNode } from "react";
import type { Severity, StageState } from "../api/types";
import { SEV_COLOR } from "../lib";

export function Logo({ onClick }: { onClick?: () => void }) {
  return (
    <button onClick={onClick} className="flex items-center gap-2 font-display text-[19px] font-bold tracking-tight" aria-label="RepoGuard home">
      <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
        <path d="M16 3l11 4v8c0 7-5 12-11 14C10 27 5 22 5 15V7z" fill="var(--color-accent)" />
        <path d="M11 16l4 4 7-8" stroke="var(--color-bg)" strokeWidth="2.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      RepoGuard
    </button>
  );
}

export function SevBadge({ severity }: { severity: Severity }) {
  const c = SEV_COLOR[severity];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[12px] font-semibold capitalize"
      style={{ color: c, borderColor: `color-mix(in srgb, ${c} 40%, transparent)`, background: `color-mix(in srgb, ${c} 10%, transparent)` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {severity}
    </span>
  );
}

export function Chip({ children, tone = "neutral", title }: { children: ReactNode; tone?: "neutral" | "warn" | "accent" | "danger"; title?: string }) {
  const tones = {
    neutral: "border-line-strong text-muted",
    warn: "border-sev-medium/40 bg-sev-medium/10 text-sev-medium",
    accent: "border-accent/40 bg-accent/10 text-accent",
    danger: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
  };
  return (
    <span title={title} className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[12px] ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <svg className="spin" width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="var(--color-line-strong)" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="var(--color-accent)" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function StageIcon({ state }: { state: StageState }) {
  const common = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", "aria-hidden": true } as const;
  switch (state) {
    case "running":
      return <Spinner size={18} />;
    case "done":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="10" fill="var(--color-ok)" fillOpacity=".15" stroke="var(--color-ok)" strokeWidth="1.5" />
          <path d="M7.5 12.5l3 3 6-6.5" stroke="var(--color-ok)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "degraded":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="10" fill="var(--color-sev-medium)" fillOpacity=".15" stroke="var(--color-sev-medium)" strokeWidth="1.5" />
          <path d="M12 7v6M12 16.5v.5" stroke="var(--color-sev-medium)" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "failed":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="10" fill="var(--color-sev-critical)" fillOpacity=".15" stroke="var(--color-sev-critical)" strokeWidth="1.5" />
          <path d="M8.5 8.5l7 7M15.5 8.5l-7 7" stroke="var(--color-sev-critical)" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "skipped":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="10" stroke="var(--color-faint)" strokeWidth="1.5" strokeDasharray="3 3" />
          <path d="M8 12h8" stroke="var(--color-faint)" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="10" stroke="var(--color-line-strong)" strokeWidth="1.5" />
        </svg>
      );
  }
}

export const btnPrimary =
  "inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2 text-[14px] font-semibold text-bg transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40";
export const btnGhost =
  "inline-flex items-center justify-center gap-2 rounded-lg border border-line-strong bg-transparent px-3.5 py-2 text-[14px] font-medium text-ink transition hover:border-accent/60 hover:bg-raised disabled:cursor-not-allowed disabled:opacity-40";
