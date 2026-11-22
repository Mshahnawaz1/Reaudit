import { API_BASE, USE_LOCAL_MOCK } from "./client";
import type { SseEventMap, SseEventName } from "./types";
import { localMock } from "../mock/local";

export type SseHandlers = {
  [K in SseEventName]?: (data: SseEventMap[K]) => void;
} & { onConnectionLost?: () => void };

const NAMES: SseEventName[] = ["stage", "hits", "agent_progress", "warning", "done", "error"];

/** Subscribes to a job's event stream. Returns a cleanup function. Closes itself after done/error. */
export function subscribeToJob(jobId: string, handlers: SseHandlers): () => void {
  if (USE_LOCAL_MOCK) return localMock.subscribe(jobId, handlers);

  const es = new EventSource(`${API_BASE}/api/audit/${encodeURIComponent(jobId)}/events`);
  let finished = false;

  const attach = <K extends SseEventName>(name: K): void => {
    es.addEventListener(name, (ev) => {
      let data: SseEventMap[K];
      try {
        data = JSON.parse((ev as MessageEvent<string>).data) as SseEventMap[K];
      } catch {
        return;
      }
      if (name === "done" || name === "error") {
        finished = true;
        es.close();
      }
      (handlers[name] as ((d: SseEventMap[K]) => void) | undefined)?.(data);
    });
  };
  NAMES.forEach(attach);

  es.onerror = () => {
    // Server replays history from the start, so auto-reconnect is safe only before completion.
    if (finished) return;
    if (es.readyState === EventSource.CLOSED) handlers.onConnectionLost?.();
  };

  return () => {
    finished = true;
    es.close();
  };
}
