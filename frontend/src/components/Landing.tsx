import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { ApiRequestError, getHealth, startAudit } from "../api/client";
import { validateRepoUrl } from "../lib";
import { Spinner, btnPrimary } from "./ui";

const EXAMPLES = [
  { label: "expressjs/express", url: "https://github.com/expressjs/express" },
  { label: "pallets/flask", url: "https://github.com/pallets/flask" },
];
const MOCK_EXAMPLES = [
  { label: "Demo repo", url: "https://github.com/acme/vulnerable-demo" },
  { label: "Degraded run", url: "https://github.com/acme/demo/mock/degraded" },
  { label: "Repo not found", url: "https://github.com/acme/demo/mock/not-found" },
  { label: "Slow run (60s)", url: "https://github.com/acme/demo/mock/slow" },
];

const POINTS = [
  { t: "Rules first", d: "Secrets, vulnerable dependencies and risky CI workflows are found by deterministic code, not guesses." },
  { t: "Agents judge, code verifies", d: "Agents confirm or dismiss each hit. Every finding must point to a real file, line and snippet or it is dropped." },
  { t: "Honest coverage", d: "You see what was scanned, what was skipped, and what only got a secrets scan." },
];

export function Landing({ prefill, notice, onStarted }: { prefill: string; notice: string | null; onStarted: (jobId: string, url: string) => void }) {
  const [url, setUrl] = useState(prefill);
  const [error, setError] = useState<string | null>(notice);
  const [loading, setLoading] = useState(false);
  const [mock, setMock] = useState(false);
  const [apiDown, setApiDown] = useState(false);

  useEffect(() => {
    let alive = true;
    getHealth()
      .then((h) => alive && setMock(h.mock))
      .catch(() => alive && setApiDown(true));
    return () => {
      alive = false;
    };
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const v = validateRepoUrl(url);
    if (v) {
      setError(v);
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const { job_id } = await startAudit(url.trim());
      onStarted(job_id, url.trim());
    } catch (err) {
      setError(err instanceof ApiRequestError ? err.message : "Something went wrong starting the audit.");
      setLoading(false);
    }
  }

  const examples = mock ? [...MOCK_EXAMPLES, ...EXAMPLES] : EXAMPLES;

  return (
    <section className="pt-14 sm:pt-24">
      <h1 className="mx-auto max-w-3xl text-center font-display text-[40px] font-bold leading-[1.02] tracking-[-0.03em] sm:text-[68px]">
        Know what a repo is hiding before you trust it.
      </h1>
      <p className="mx-auto mt-6 max-w-xl text-center text-[17px] text-muted">
        Paste a public GitHub link. RepoGuard checks for leaked secrets, vulnerable dependencies and exploitable CI, then ranks what to fix first.
      </p>

      <form onSubmit={submit} className="mx-auto mt-10 max-w-2xl" noValidate>
        <div
          className={`flex items-center gap-2 rounded-2xl border bg-surface/80 p-2 pl-4 shadow-[0_0_80px_-20px_rgba(139,156,255,0.5)] backdrop-blur transition focus-within:border-accent ${error ? "border-sev-critical/60" : "border-line-strong"}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="shrink-0 text-faint" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></svg>
          <label htmlFor="repo-url" className="sr-only">
            GitHub repository URL
          </label>
          <input
            id="repo-url"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setError(null);
            }}
            placeholder="https://github.com/owner/repo"
            spellCheck={false}
            autoComplete="off"
            autoFocus
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "url-error" : undefined}
            className="min-w-0 flex-1 bg-transparent py-2.5 font-mono text-[14px] text-ink outline-none placeholder:text-faint"
          />
          <button type="submit" disabled={loading} className={`${btnPrimary} px-5 py-2.5`}>
            {loading ? <Spinner /> : null}
            {loading ? "Starting" : "Audit repo"}
          </button>
        </div>
        {error && (
          <p id="url-error" role="alert" className="mt-3 text-center text-[14px] text-sev-critical">
            {error}
          </p>
        )}
        {apiDown && !error && (
          <p className="mt-3 text-center text-[13px] text-sev-medium">The API is not responding. Start the backend, then try again.</p>
        )}
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
          <span className="text-[13px] text-faint">{mock ? "Mock mode. Try" : "Try"}</span>
          {examples.map((ex) => (
            <button
              key={ex.url}
              type="button"
              onClick={() => {
                setUrl(ex.url);
                setError(null);
              }}
              className="rounded-full border border-line-strong px-3 py-1 text-[13px] text-muted transition hover:border-accent/60 hover:text-ink"
            >
              {ex.label}
            </button>
          ))}
        </div>
      </form>

      <div className="mx-auto mt-24 grid max-w-4xl gap-4 sm:grid-cols-3">
        {POINTS.map((p) => (
          <div key={p.t} className="card p-5">
            <h2 className="font-display text-[17px] font-semibold tracking-tight">{p.t}</h2>
            <p className="mt-2 text-[14px] text-muted">{p.d}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
