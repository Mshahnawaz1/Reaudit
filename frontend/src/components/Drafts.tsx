import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { IssueDraft } from "../api/types";
import { copyText } from "../lib";
import { Spinner, btnGhost, btnPrimary } from "./ui";

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      prev?.focus();
    };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 p-0 backdrop-blur-sm sm:items-center sm:p-6" onClick={onClose}>
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
        className="card max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-b-none border-line-strong p-6 outline-none sm:rounded-b-[14px]"
      >
        {children}
      </div>
    </div>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");
  return (
    <button
      className={btnGhost}
      onClick={async () => {
        setState((await copyText(text)) ? "ok" : "fail");
        setTimeout(() => setState("idle"), 1800);
      }}
    >
      {state === "ok" ? "Copied" : state === "fail" ? "Copy failed" : label}
    </button>
  );
}

export function DraftFlow({
  count,
  titles,
  onClose,
  onCreate,
}: {
  count: number;
  titles: string[];
  onClose: () => void;
  onCreate: () => Promise<IssueDraft[]>;
}) {
  const [step, setStep] = useState<"confirm" | "loading" | "preview">("confirm");
  const [drafts, setDrafts] = useState<IssueDraft[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    setStep("loading");
    setError(null);
    try {
      setDrafts(await onCreate());
      setStep("preview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create drafts.");
      setStep("confirm");
    }
  }

  if (step !== "preview") {
    return (
      <Modal title="Confirm issue drafts" onClose={onClose}>
        <h2 className="font-display text-[22px] font-bold tracking-tight">Draft {count} GitHub {count === 1 ? "issue" : "issues"}?</h2>
        <p className="mt-2 text-muted">This is a dry run. RepoGuard generates the issue text for you to copy. Nothing is posted to GitHub.</p>
        <ul className="mt-4 max-h-48 list-disc space-y-1 overflow-y-auto pl-5 text-[14px]">
          {titles.map((t, i) => (
            <li key={i}>{t}</li>
          ))}
        </ul>
        {error && (
          <p role="alert" className="mt-4 text-sev-critical">
            {error}
          </p>
        )}
        <div className="mt-6 flex gap-3">
          <button className={btnPrimary} onClick={confirm} disabled={step === "loading"}>
            {step === "loading" && <Spinner />}
            Confirm and generate drafts
          </button>
          <button className={btnGhost} onClick={onClose}>
            Cancel
          </button>
        </div>
      </Modal>
    );
  }
  const all = drafts.map((d) => `# ${d.title}\nLabels: ${d.labels.join(", ")}\n\n${d.body_markdown}`).join("\n\n---\n\n");
  return (
    <Modal title="Issue drafts" onClose={onClose}>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="font-display text-[22px] font-bold tracking-tight">Issue drafts</h2>
        <span className="rounded-full border border-sev-medium/40 bg-sev-medium/10 px-2.5 py-0.5 text-[12px] text-sev-medium">Dry run: not posted</span>
        <div className="ml-auto">
          <CopyButton text={all} label="Copy all" />
        </div>
      </div>
      <div className="mt-4 space-y-4">
        {drafts.map((d) => (
          <article key={d.finding_id} className="rounded-lg border border-line bg-bg p-4">
            <div className="flex items-start gap-3">
              <h3 className="flex-1 font-semibold">{d.title}</h3>
              <CopyButton text={`${d.title}\n\n${d.body_markdown}`} label="Copy" />
            </div>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {d.labels.map((l) => (
                <span key={l} className="rounded-full border border-line-strong px-2 py-0.5 text-[12px] text-muted">
                  {l}
                </span>
              ))}
            </div>
            <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono text-[12.5px] text-ink/85">{d.body_markdown}</pre>
          </article>
        ))}
      </div>
      <div className="mt-6">
        <button className={btnPrimary} onClick={onClose}>
          Done
        </button>
      </div>
    </Modal>
  );
}
