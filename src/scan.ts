/**
 * Cheap heuristics for instructions hidden inside a tool definition.
 *
 * Pinning protects against a tool changing later, but it trusts whatever the
 * tool said the first time. These checks flag definitions that already look
 * like they are talking to the model instead of describing a tool.
 * They produce warnings, never blocks: heuristics have false positives.
 */

import { includePercentDecoded } from "./percent.js";

interface Check {
  id: string;
  pattern: RegExp;
  message: string;
}

const CHECKS: Check[] = [
  {
    id: "invisible-characters",
    pattern: /[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/u,
    message: "contains invisible or text-direction characters, which can hide instructions from a human reviewer",
  },
  {
    id: "override-instructions",
    pattern: /ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidance)/i,
    message: "tells the model to ignore earlier instructions",
  },
  {
    id: "hide-from-user",
    pattern: /(do\s+not|don't|never)\s+(tell|mention|inform|reveal|show|notify)[^.\n]{0,60}\b(user|human|operator)\b/i,
    message: "tells the model to hide something from the user",
  },
  {
    id: "pseudo-system-tag",
    pattern: /<\s*(important|system|secret|instructions?|admin)\s*>/i,
    message: "contains a tag styled like a system instruction",
  },
  {
    id: "sensitive-path",
    pattern: /~\/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.aws\/credentials|\bmcp\.json\b|(^|[\s"'`/])\.env\b/i,
    message: "mentions credential files or keys",
  },
  {
    id: "cross-tool-instruction",
    pattern: /(before|when|whenever|after)\s+(using|calling|invoking|you\s+use|you\s+call)\s+(this|any|the|another|other)\s+[^.\n]{0,40}\btools?\b[^.\n]{0,120}\b(read|send|include|pass|attach|forward|upload)\b/i,
    message: "gives the model extra steps to carry out around tool use",
  },
];

/** One layer of standard base64 when the bytes are UTF-8 text; null for anything else. */
export function decodedBlob(value: string): string | null {
  const compact = value.replace(/\s+/g, "");
  if (compact.length < 8 || compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null;
  const bytes = Buffer.from(compact, "base64");
  if (bytes.length === 0 || bytes.length > 2_000_000) return null;
  if (bytes.toString("base64").replace(/=+$/, "") !== compact.replace(/=+$/, "")) return null;
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) return null;
  return text;
}

function encodedText(key: string, value: unknown): string | null {
  if ((key !== "blob" && key !== "data") || typeof value !== "string") return null;
  return decodedBlob(value);
}

/** Includes text stored in a base64 blob, in image and audio data, and in object keys. */
export function collectText(value: unknown): string[] {
  const out: string[] = [];
  collectStrings(value, out);
  return out;
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out);
  } else if (value !== null && typeof value === "object") {
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      collectStrings(v, out);
      const text = encodedText(key, v);
      if (text !== null) out.push(text);
      out.push(key);
    }
  }
}

/** Put the notice inside base64 text (a resource blob, or image and audio data) when that text is suspicious. */
export function noticeOnBlobs(value: unknown, notice: string): unknown {
  if (Array.isArray(value)) return value.map((item) => noticeOnBlobs(item, notice));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, v]) => {
        const text = encodedText(key, v);
        if (text !== null && scanResult(text).length > 0) {
          return [key, Buffer.from(notice + "\n\n" + text, "utf8").toString("base64")];
        }
        return [key, noticeOnBlobs(v, notice)];
      }),
    );
  }
  return value;
}

export interface Finding {
  id: string;
  message: string;
}

/** Scan every string in a tool definition (description, schema descriptions, defaults, enums). */
export function scanTool(tool: unknown): Finding[] {
  const text = includePercentDecoded(collectText(tool)).join("\n");
  const findings: Finding[] = [];
  for (const check of CHECKS) {
    if (check.pattern.test(text)) findings.push({ id: check.id, message: check.message });
  }
  return findings;
}

/**
 * Checks for tool *results*. Results are arbitrary content (web pages, files,
 * tickets), so these are narrower than the definition checks: only patterns
 * that have no business appearing in data returned to a model.
 */
const RESULT_CHECKS: Check[] = [
  {
    id: "hidden-characters",
    // Unicode "tag" characters and text-direction overrides. Zero-width joiners are left out: emoji use them.
    pattern: /[\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/u,
    message: "contains hidden or text-direction characters",
  },
  {
    id: "override-instructions",
    pattern: /ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidance)/i,
    message: "tells the model to ignore earlier instructions",
  },
  {
    id: "hide-from-user",
    pattern: /(do\s+not|don't|never)\s+(tell|mention|inform|reveal|show|notify)[^.\n]{0,60}\b(user|human|operator)\b/i,
    message: "tells the model to hide something from the user",
  },
  {
    id: "pseudo-system-tag",
    pattern: /<\s*(important|system|secret|admin)\s*>|\[\s*(system|admin)\s+(message|instruction|override)\s*\]/i,
    message: "contains text styled like a system instruction",
  },
  {
    id: "exfiltration-instruction",
    pattern: /\b(send|post|upload|forward|email|exfiltrate|transmit)\b[^.\n]{0,80}\b(api[ _-]?keys?|passwords?|access tokens?|credentials|secrets?|ssh keys?|private keys?|\.env)\b/i,
    message: "tells the model to send credentials somewhere",
  },
];

/** Scan the text a tool returned for instructions aimed at the model. */
export function scanResult(result: unknown): Finding[] {
  const text = includePercentDecoded(collectText(result)).join("\n").slice(0, 2_000_000);
  const findings: Finding[] = [];
  for (const check of RESULT_CHECKS) {
    if (check.pattern.test(text)) findings.push({ id: check.id, message: check.message });
  }
  return findings;
}
