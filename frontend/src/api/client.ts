import type {
  ApiError,
  AuditReport,
  ErrorCode,
  HealthResponse,
  IssueDraftsResponse,
  StartAuditResponse,
} from "./types";
import { localMock } from "../mock/local";

export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";
export const USE_LOCAL_MOCK: boolean = import.meta.env.VITE_USE_LOCAL_MOCK === "1";

export class ApiRequestError extends Error {
  code: ErrorCode | "network_error";
  detail: string | undefined;
  status: number;
  constructor(code: ErrorCode | "network_error", message: string, status: number, detail?: string) {
    super(message);
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

function isApiError(v: unknown): v is ApiError {
  if (typeof v !== "object" || v === null || !("error" in v)) return false;
  const e = (v as { error: unknown }).error;
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiRequestError(
      "network_error",
      `Cannot reach the RepoGuard API at ${API_BASE}. Is the backend running?`,
      0,
    );
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (!res.ok) {
    if (isApiError(body)) {
      throw new ApiRequestError(body.error.code, body.error.message, res.status, body.error.detail);
    }
    throw new ApiRequestError("internal_error", `Request failed (${res.status})`, res.status);
  }
  return body as T;
}

export function getHealth(): Promise<HealthResponse> {
  if (USE_LOCAL_MOCK) return localMock.getHealth();
  return request<HealthResponse>("/api/health");
}

export function startAudit(repoUrl: string): Promise<StartAuditResponse> {
  if (USE_LOCAL_MOCK) return localMock.startAudit(repoUrl);
  return request<StartAuditResponse>("/api/audit", {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl }),
  });
}

export function getReport(jobId: string): Promise<AuditReport> {
  if (USE_LOCAL_MOCK) return localMock.getReport(jobId);
  return request<AuditReport>(`/api/audit/${encodeURIComponent(jobId)}`);
}

export function createDrafts(jobId: string, findingIds: string[]): Promise<IssueDraftsResponse> {
  if (USE_LOCAL_MOCK) return localMock.createDrafts(jobId, findingIds);
  return request<IssueDraftsResponse>(`/api/audit/${encodeURIComponent(jobId)}/issue-drafts`, {
    method: "POST",
    body: JSON.stringify({ finding_ids: findingIds }),
  });
}
