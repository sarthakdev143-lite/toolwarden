import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * What the operator can see about one state directory: who it belongs to,
 * the recent allow and deny decisions, and the limits that are still true.
 * Hosting the service does not narrow these limits.
 */
export const KNOWN_LIMITS = [
  "Pinning catches changes after the first listing. A first definition that does not match the hidden-instruction checks is still trusted, so a reworded instruction can get through.",
  "Argument rules, result checks, and flow tracking are pattern matching. They do not stop every attack. A phrase that is reworded, or built by the server without sending the text, can still get past them.",
  "In the default annotate mode, suspicious text from a server still reaches the model with a notice in front. That notice is advice, not a block.",
  "A local server that reads files on its own, without a tool call through this proxy, is not something toolwarden can see.",
  "Remote MCP servers that need a browser sign-in are passed through. That OAuth sign-in belongs to the MCP server. It is not a Toolwarden account.",
  "The audit log is a record for the operator on this machine. It is not tamper-proof evidence.",
] as const;

const DECISION_EVENTS = new Set([
  "pinned",
  "tool_changed",
  "tool_new",
  "tool_flagged",
  "tool_removed",
  "definition_warning",
  "call",
  "call_blocked",
  "call_denied",
  "call_warning",
  "result_warning",
  "result_blocked",
  "flow",
  "flow_denied",
]);

export interface OperatorAccount {
  id: string;
  email: string;
}

export interface OperatorDecision {
  ts: string;
  server: string;
  event: string;
  tool?: string;
  summary: string;
}

export function readAuditRecords(stateDir: string, limit: number): Record<string, unknown>[] {
  const path = join(stateDir, "audit.log");
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean).slice(-limit);
  const out: Record<string, unknown>[] = [];
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as unknown;
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        out.push(parsed as Record<string, unknown>);
      }
    } catch {
      /* skip a damaged line */
    }
  }
  return out;
}

/** The identity file written beside an account's pins. Password hashes are never copied out of it. */
export function readOperatorAccount(stateDir: string): OperatorAccount | null {
  const path = join(stateDir, "account.json");
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    if (typeof parsed.id !== "string" || parsed.id === "") return null;
    if (typeof parsed.email !== "string" || parsed.email === "") return null;
    return { id: parsed.id, email: parsed.email };
  } catch {
    return null;
  }
}

function summaryOf(record: Record<string, unknown>): string {
  const reason = typeof record.reason === "string" ? record.reason : "";
  const rule = typeof record.rule === "string" && record.rule !== "" ? ` (rule ${record.rule})` : "";
  let text: string;
  switch (record.event) {
    case "call":
      text = "Allowed the call through.";
      break;
    case "call_blocked":
      text = reason || "Blocked the call.";
      break;
    case "call_denied":
      text = (reason ? `Denied the call: ${reason}` : "Denied the call.") + rule;
      break;
    case "call_warning":
    case "result_warning":
    case "definition_warning":
      text = (reason || "Recorded a warning.") + rule;
      break;
    case "result_blocked":
      text = reason || "Withheld text from the server.";
      break;
    case "flow_denied":
      text = "Blocked a value that came from another server." + rule;
      break;
    case "flow":
      text = record.warned === true ? "A credential moved between servers." : "A value moved between servers.";
      break;
    case "tool_changed":
      text = "A tool definition changed after approval.";
      break;
    case "tool_new":
      text = "A new tool appeared after the server was first approved.";
      break;
    case "tool_flagged":
      text = "A first definition matched a hidden-instruction check.";
      break;
    case "tool_removed":
      text = "A tool disappeared from the server.";
      break;
    case "pinned":
      text = typeof record.count === "number"
        ? `Recorded ${record.count} tool definitions on first use.`
        : "Recorded a tool definition.";
      break;
    default:
      text = reason || String(record.event ?? "decision");
  }
  return text.length > 300 ? text.slice(0, 300) + "…" : text;
}

/** Newest decisions first. Session starts are omitted: they are not an allow or a deny. */
export function readDecisions(stateDir: string, limit = 30): OperatorDecision[] {
  const matched: OperatorDecision[] = [];
  for (const record of readAuditRecords(stateDir, 500)) {
    if (!DECISION_EVENTS.has(String(record.event))) continue;
    const decision: OperatorDecision = {
      ts: typeof record.ts === "string" ? record.ts : "",
      server: typeof record.server === "string" ? record.server : "",
      event: typeof record.event === "string" ? record.event : "",
      summary: summaryOf(record),
    };
    if (typeof record.tool === "string" && record.tool !== "") decision.tool = record.tool;
    matched.push(decision);
  }
  return matched.slice(-limit).reverse();
}
