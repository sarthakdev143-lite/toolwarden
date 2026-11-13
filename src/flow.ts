import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { slug } from "./pins.js";
import { collectText, matchForms } from "./scan.js";

/**
 * Cross-server data tracking.
 *
 * Each wrapped server runs in its own toolwarden process, so they share what
 * they have seen through small files in the state directory. When a server
 * shows a tool definition, including one whose name is not a string, a catalog description, an introduction, including a credential path, a progress update, including its token, which is left unchanged so the update still matches, including a credential path in that token, a sampling request, including a credential path in its system prompt and in a message the model is asked to answer, and in any other field, a question the server asks, including a credential path, a completion
 * suggestion, a completion error, a cancellation, including a credential path in its id, which is left unchanged, a resource update, including a credential path, any
 * other notification, including a credential path, any other server request, including a credential path, a request for filesystem
 * roots, the reply to any other client request, the reply to a resource
 * subscription, or a field beside a server message, including a credential path, a result or an error on a server request or notification, including a credential path, or the method name on a server message, including a method that is not a string and a credential path, or the protocol version, including a credential path, or the id, including a credential path, which is left unchanged so the answer still matches, or a value that is not a JSON-RPC object, including a credential path, or parameters that are an array or a string, including a credential path, or a result or an error that is an array or a string, including a credential path in a definition, or a field beside the items in a tool, resource, prompt, or template list, including a credential path, or a list item that is not an object, including a credential path, or an error from a tool, resource, prompt, or template list, or from the opening handshake, or an error beside a result, or an object key, or returns text, including a credential path in a prompt result, including a result that is not an object and a field beside that text, and including a credential path in the uri of a returned resource, including a resource that is not a list and when the result itself is that list and when an item in that resource is a list and when an item in that list is a list and when that list is wrapped again and when that resource is not an object and when an item in that resource is not an object and when that text is not a string and when that blob is not a string and when that text is a list and when that blob is a list, and in a field beside that resource, and including a credential path in a field beside tool output, including when that output is not a list and when the result itself is that list and when an item in that output is a list and when an item in that list is a list and when that list is wrapped again and when that text is not a string and when that data is not a string, including base64 in that object, and when that blob is not a string, including base64 in that blob object and in an object inside that object, and when that uri is not a string and when that text is a list and when that data is a list, including base64 in that list and in an object in that list, including an object inside that object, and when that blob is a list, including base64 in that blob list and in an object in that list, including an object inside that object, and when that uri is a list and when an item in that output is not an object and when that output is not an object, and including a credential path in a field beside an embedded resource, including when that resource is a list and when an item in that resource is a list and when an item in that list is a list and when that list is wrapped again and when that resource is not an object and when that text is not a string and when that blob is not a string and when that text is a list and when that blob is a list and when that uri is not a string and when that uri is a list, we remember
 * fingerprints (hashes, never the values) of the distinctive tokens in it. A token
 * written with a compatibility character or an invisible character is the same
 * token. When
 * a call to a *different* server carries one of those tokens in its arguments,
 * in a filesystem root, including an answer that is not a list, a field beside that list, an error answering the request, a field beside that error, and an error beside the result, in a tool, resource, prompt, or template list, in the opening handshake, in any other client message, including a value that is not a JSON-RPC object, the protocol version, a tool call whose name is not a string, in a field beside the
 * parameters, in the answer to a question, including its id, in a sampling reply, including its id, or in the
 * answer to any other server request, including the id of that answer, a field beside that answer, or an error beside the result, or in
 * an object key,
 * that is a data flow
 * between servers: the pattern behind "read a secret with one tool, send it out
 * with another".
 */

export type FlowKind = "secret" | "value";

export interface FlowHit {
  from: string;
  kind: FlowKind;
  ageMs: number;
}

/** Formats that are almost certainly credentials. */
export const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{20,}?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bxox[abpors]-[A-Za-z0-9-]{10,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];

/** Long mixed tokens: IDs, hashes, keys in formats we do not know by name. */
const TOKEN_PATTERN = /[A-Za-z0-9+_\-=]{24,}/g;

const MAX_TOKENS_PER_MESSAGE = 500;
const MAX_SCAN_CHARS = 2_000_000;
const PRUNE_ABOVE_BYTES = 1_000_000;

function fingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 16);
}

/** Extract fingerprints of secret-shaped strings and of long mixed tokens. */
export function extractFingerprints(value: unknown): { secrets: string[]; values: string[] } {
  const text = collectText(value).flatMap(matchForms).join("\n").slice(0, MAX_SCAN_CHARS);

  const secrets = new Set<string>();
  for (const pattern of SECRET_PATTERNS) {
    for (const m of text.matchAll(pattern)) {
      // Normalize whitespace so a key survives being re-wrapped or JSON-escaped.
      secrets.add(fingerprint(m[0].replace(/\s+/g, "")));
      if (secrets.size >= MAX_TOKENS_PER_MESSAGE) break;
    }
  }

  const values = new Set<string>();
  for (const m of text.matchAll(TOKEN_PATTERN)) {
    const t = m[0];
    // Require letters and digits: skips plain words, dashes and separators.
    if (!/[A-Za-z]/.test(t) || !/[0-9]/.test(t)) continue;
    values.add(fingerprint(t));
    if (values.size >= MAX_TOKENS_PER_MESSAGE) break;
  }
  return { secrets: [...secrets], values: [...values] };
}

interface FlowLine {
  ts: number;
  s: string[];
  v: string[];
}

export class FlowTracker {
  private readonly dir: string;
  private readonly ownFile: string;

  constructor(
    stateDir: string,
    private readonly server: string,
    /** How long a returned value stays "recent". */
    private readonly windowMs = 30 * 60 * 1000,
  ) {
    this.dir = join(stateDir, "flow");
    this.ownFile = join(this.dir, slug(server) + ".jsonl");
  }

  /** Remember what this server just returned. */
  record(result: unknown): void {
    const { secrets, values } = extractFingerprints(result);
    if (secrets.length === 0 && values.length === 0) return;
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      this.pruneIfLarge();
      const line: FlowLine = { ts: Date.now(), s: secrets, v: values };
      appendFileSync(this.ownFile, JSON.stringify(line) + "\n", { mode: 0o600 });
    } catch {
      /* tracking is best-effort; never break the proxy over it */
    }
  }

  /** Does this value contain something another server returned recently? */
  check(args: unknown): FlowHit[] {
    const { secrets, values } = extractFingerprints(args);
    if (secrets.length === 0 && values.length === 0) return [];
    const secretSet = new Set(secrets);
    const valueSet = new Set(values);
    const now = Date.now();
    const hits = new Map<string, FlowHit>();

    let files: string[];
    try {
      files = existsSync(this.dir) ? readdirSync(this.dir).filter((f) => f.endsWith(".jsonl")) : [];
    } catch {
      return [];
    }

    for (const file of files) {
      const from = file.slice(0, -6);
      if (from === slug(this.server)) continue;
      let content: string;
      try {
        content = readFileSync(join(this.dir, file), "utf8");
      } catch {
        continue;
      }
      for (const raw of content.split("\n")) {
        if (!raw) continue;
        let line: FlowLine;
        try {
          line = JSON.parse(raw) as FlowLine;
        } catch {
          continue;
        }
        const ageMs = now - line.ts;
        if (ageMs > this.windowMs || ageMs < 0) continue;
        // A secret-shaped value counts as a secret flow even if only its token form matched.
        const isSecret = line.s.some((h) => secretSet.has(h));
        const isValue = !isSecret && line.v.some((h) => valueSet.has(h));
        if (!isSecret && !isValue) continue;
        const kind: FlowKind = isSecret ? "secret" : "value";
        const key = from + ":" + kind;
        const existing = hits.get(key);
        if (!existing || ageMs < existing.ageMs) hits.set(key, { from, kind, ageMs });
      }
    }
    // If the same server produced both a secret hit and a value hit, the secret one is enough.
    return [...hits.values()].filter((h) => h.kind === "secret" || !hits.has(h.from + ":secret"));
  }

  private pruneIfLarge(): void {
    if (!existsSync(this.ownFile) || statSync(this.ownFile).size < PRUNE_ABOVE_BYTES) return;
    const cutoff = Date.now() - this.windowMs;
    const kept = readFileSync(this.ownFile, "utf8")
      .split("\n")
      .filter((raw) => {
        if (!raw) return false;
        try {
          return (JSON.parse(raw) as FlowLine).ts >= cutoff;
        } catch {
          return false;
        }
      });
    writeFileSync(this.ownFile, kept.length > 0 ? kept.join("\n") + "\n" : "", { mode: 0o600 });
  }
}
