import type { Area, Severity, StageId } from "./api/types";

const GITHUB_RE = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]+?(?:\.git)?(?:\/tree\/[^\s]+|\/mock\/(?:not-found|degraded|slow))?\/?$/;

export function validateRepoUrl(raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Paste a GitHub repository URL.";
  if (!/^https:\/\//.test(v)) return "The URL must start with https://";
  if (!/^https:\/\/github\.com\//.test(v)) return "Only public github.com repositories are supported.";
  if (!GITHUB_RE.test(v)) return "Use the form https://github.com/owner/repo";
  return null;
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)",
  info: "var(--color-sev-info)",
};

export const AREA_LABEL: Record<Area, string> = {
  secrets: "Secrets",
  deps: "Dependencies",
  ci: "CI/CD",
  code: "App code",
  config: "Config",
  meta: "Attack in repo",
};

export const STAGE_ORDER: StageId[] = [
  "ingest",
  "deterministic",
  "ci_agent",
  "secrets_agent",
  "code_agent",
  "verify",
  "synthesize",
];
export const STAGE_LABEL: Record<StageId, string> = {
  ingest: "Fetch repository",
  deterministic: "Rule-based scan",
  ci_agent: "CI/CD review",
  secrets_agent: "Secrets triage",
  code_agent: "App code review",
  verify: "Verify evidence",
  synthesize: "Rank and summarize",
};

export function scoreColor(score: number): string {
  if (score >= 80) return "var(--color-ok)";
  if (score >= 50) return "var(--color-sev-medium)";
  return "var(--color-sev-critical)";
}

export function permalink(owner: string, name: string, commit: string, file: string, line: number): string {
  const path = file.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/blob/${encodeURIComponent(commit)}/${path}#L${line}`;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
