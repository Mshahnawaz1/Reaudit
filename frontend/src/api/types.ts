export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Area = "secrets" | "deps" | "ci" | "code" | "config" | "meta";
export type StageId =
  | "ingest"
  | "deterministic"
  | "ci_agent"
  | "code_agent"
  | "secrets_agent"
  | "verify"
  | "synthesize";
export type StageState = "pending" | "running" | "done" | "degraded" | "failed" | "skipped";

export interface Finding {
  id: string;
  area: Area;
  severity: Severity;
  confidence: number;
  rule_ids: string[];
  source: "rule" | "agent" | "rule+agent";
  title: string;
  explanation: string;
  suggested_fix: string;
  file: string;
  line: number;
  end_line: number | null;
  snippet: string;
  cwe: string | null;
  agent_note: string | null;
  verified: true;
}

export interface DismissedHit {
  rule_id: string;
  file: string;
  line: number;
  reason: string;
}

export interface StageStatus {
  id: StageId;
  state: StageState;
  message: string | null;
  duration_ms: number | null;
}

export interface Coverage {
  files_total: number;
  files_scanned: number;
  files_skipped: number;
  skipped_reasons: Record<string, number>;
  languages: string[];
  reduced_coverage_languages: string[];
  caps_hit: string[];
}

export interface RepoInfo {
  url: string;
  owner: string;
  name: string;
  commit: string;
  branch: string;
}

export interface AuditReport {
  job_id: string;
  repo: RepoInfo;
  score: number;
  summary: string;
  top5: string[];
  findings: Finding[];
  dismissed: DismissedHit[];
  dropped_unverified: number;
  coverage: Coverage;
  stages: StageStatus[];
  counts: Record<Severity, number>;
  generated_at: string;
}

export interface IssueDraft {
  finding_id: string;
  title: string;
  labels: string[];
  body_markdown: string;
}

export type ErrorCode =
  | "invalid_url"
  | "unsupported_host"
  | "repo_not_found"
  | "repo_private_or_forbidden"
  | "repo_empty"
  | "repo_too_large"
  | "clone_timeout"
  | "job_not_found"
  | "job_not_ready"
  | "rate_limited"
  | "llm_unavailable"
  | "internal_error";

export interface ApiError {
  error: { code: ErrorCode; message: string; detail?: string };
}

export interface HealthResponse {
  status: "ok";
  mock: boolean;
  model: string;
}

export interface StartAuditResponse {
  job_id: string;
}

export interface IssueDraftsResponse {
  drafts: IssueDraft[];
}

export interface SseEnvelope {
  ts: string;
  stage?: StageId;
}
export interface StageEvent extends SseEnvelope {
  stage: StageId;
  state: StageState;
  message?: string;
}
export interface HitsEvent extends SseEnvelope {
  stage: "deterministic";
  by_area: Partial<Record<Area, number>>;
  total: number;
}
export interface AgentProgressEvent extends SseEnvelope {
  stage: StageId;
  message: string;
}
export interface WarningEvent extends SseEnvelope {
  stage: StageId;
  code: string;
  message: string;
}
export interface DoneEvent extends SseEnvelope {
  job_id: string;
  score: number;
}
export interface ErrorEvent extends SseEnvelope {
  code: ErrorCode;
  message: string;
}

export interface SseEventMap {
  stage: StageEvent;
  hits: HitsEvent;
  agent_progress: AgentProgressEvent;
  warning: WarningEvent;
  done: DoneEvent;
  error: ErrorEvent;
}
export type SseEventName = keyof SseEventMap;
