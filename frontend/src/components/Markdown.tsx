import type { ReactNode } from "react";

/** Tiny safe markdown: paragraphs, ``` fences, `code`, **bold**, - lists. Everything is rendered as text nodes. */
function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`\n]+`|\*\*[^*\n]+\*\*)/g;
  let last = 0;
  let i = 0;
  for (const m of text.matchAll(re)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(text.slice(last, idx));
    const tok = m[0];
    if (tok.startsWith("`")) {
      out.push(
        <code key={`${keyBase}-${i++}`} className="rounded bg-raised px-1.5 py-0.5 font-mono text-[0.85em] text-accent">
          {tok.slice(1, -1)}
        </code>,
      );
    } else {
      out.push(<strong key={`${keyBase}-${i++}`}>{tok.slice(2, -2)}</strong>);
    }
    last = idx + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

type Block =
  | { t: "code"; lang: string; body: string }
  | { t: "p"; body: string }
  | { t: "ul"; items: string[] };

function parse(src: string): Block[] {
  const blocks: Block[] = [];
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    if (line.trim().startsWith("```")) {
      const lang = line.trim().slice(3).trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? "").trim().startsWith("```")) {
        body.push(lines[i] ?? "");
        i++;
      }
      i++;
      blocks.push({ t: "code", lang, body: body.join("\n") });
    } else if (/^\s*[-*] /.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*] /.test(lines[i] ?? "")) {
        items.push((lines[i] ?? "").replace(/^\s*[-*] /, ""));
        i++;
      }
      blocks.push({ t: "ul", items });
    } else if (line.trim() === "") {
      i++;
    } else {
      const body: string[] = [];
      while (
        i < lines.length &&
        (lines[i] ?? "").trim() !== "" &&
        !(lines[i] ?? "").trim().startsWith("```") &&
        !/^\s*[-*] /.test(lines[i] ?? "")
      ) {
        body.push((lines[i] ?? "").replace(/^#{1,6}\s+/, ""));
        i++;
      }
      blocks.push({ t: "p", body: body.join(" ") });
    }
  }
  return blocks;
}

export function Markdown({ source }: { source: string }) {
  const blocks = parse(source);
  return (
    <div className="space-y-3 text-[14px] leading-relaxed text-ink/90">
      {blocks.map((b, i) => {
        if (b.t === "code") {
          return (
            <pre key={i} className="overflow-x-auto rounded-lg border border-line bg-bg p-3 font-mono text-[12.5px] leading-relaxed text-ink">
              <code>{b.body}</code>
            </pre>
          );
        }
        if (b.t === "ul") {
          return (
            <ul key={i} className="list-disc space-y-1 pl-5">
              {b.items.map((it, j) => (
                <li key={j}>{inline(it, `${i}-${j}`)}</li>
              ))}
            </ul>
          );
        }
        return <p key={i}>{inline(b.body, String(i))}</p>;
      })}
    </div>
  );
}
