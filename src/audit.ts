import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { SECRET_PATTERNS } from "./flow.js";
import { decodedBlob, matchForms } from "./scan.js";

export type AuditEvent =
  | "session_start"
  | "pinned"
  | "tool_changed"
  | "tool_new"
  | "tool_removed"
  | "definition_warning"
  | "call"
  | "call_blocked"
  | "call_denied"
  | "call_warning"
  | "result_warning"
  | "result_blocked"
  | "flow"
  | "flow_denied";

export interface AuditRecord {
  event: AuditEvent;
  tool?: string;
  [key: string]: unknown;
}

const MAX_ARG_CHARS = 2000;

function redactString(value: string): string {
  const blob = decodedBlob(value);
  const source = blob ?? value;
  for (const form of matchForms(source)) {
    let out = form;
    for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, "[credential removed]");
    if (out !== form) return out;
  }
  return value;
}

function redact(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map(redact);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [redactString(k), redact(v)]),
    );
  }
  return value;
}

/**
 * Prepare call arguments for the log: credentials are removed, including from
 * object keys, from text written with a compatibility character or an
 * invisible character, and from URL-safe base64 or base64 with the padding
 * left off, and long payloads are truncated.
 */
export function summarizeArgs(args: unknown): unknown {
  const safe = redact(args ?? null);
  const text = JSON.stringify(safe);
  if (text.length <= MAX_ARG_CHARS) return safe;
  return { truncated: true, preview: text.slice(0, MAX_ARG_CHARS) };
}

export class AuditLog {
  readonly path: string;

  constructor(
    stateDir: string,
    private readonly server: string,
    /** Human-readable alerts go here (stderr in production, a buffer in tests). */
    private readonly alertSink: (line: string) => void,
  ) {
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    this.path = join(stateDir, "audit.log");
  }

  record(rec: AuditRecord): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), server: this.server, ...rec });
    try {
      appendFileSync(this.path, line + "\n", { mode: 0o600 });
    } catch (err) {
      this.alertSink(`[toolwarden] could not write audit log: ${(err as Error).message}`);
    }
  }

  /** Print an alert for the human and record it. */
  alert(message: string, rec: AuditRecord): void {
    this.alertSink(`[toolwarden] ${message}`);
    this.record(rec);
  }
}
