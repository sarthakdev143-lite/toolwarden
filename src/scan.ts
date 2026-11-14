/**
 * Cheap heuristics for instructions hidden inside a tool definition.
 *
 * Pinning protects against a tool changing later, but it trusts whatever the
 * tool said the first time. These checks flag definitions that already look
 * like they are talking to the model instead of describing a tool.
 * They produce warnings, never blocks: heuristics have false positives.
 */

import { percentDecoded } from "./percent.js";

interface Check {
  id: string;
  pattern: RegExp;
  message: string;
}

/** Characters that can hide or reorder text. The zero-width joiner is not included, so emoji sequences stay intact. */
const INVISIBLE_SOURCE =
  "[\\u200B\\u200C\\u200E\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF]|[\\u{E0000}-\\u{E007F}]";

/** Fold compatibility characters and drop invisible characters, so a lookalike string can be matched. */
export function comparableText(value: string): string {
  return value.normalize("NFKC").replace(new RegExp(INVISIBLE_SOURCE, "gu"), "");
}

function hasNonAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 127) return true;
  }
  return false;
}

/**
 * The string itself, plus the same string with percent-encoding undone and with
 * compatibility characters and invisible characters folded. Each result is
 * folded again, so text cannot hide behind one layer of either disguise.
 */
export function matchForms(value: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (s: string) => {
    if (seen.has(s)) return;
    seen.add(s);
    out.push(s);
  };
  add(value);
  for (let i = 0; i < out.length && i < 8; i++) {
    const s = out[i];
    if (s === undefined) continue;
    const decoded = percentDecoded(s);
    if (decoded !== null) add(decoded);
    if (hasNonAscii(s)) {
      const folded = comparableText(s);
      if (folded !== s) add(folded);
    }
  }
  return out;
}

const CHECKS: Check[] = [
  {
    id: "invisible-characters",
    pattern: new RegExp(INVISIBLE_SOURCE, "u"),
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

/** One layer of base64, including the URL-safe alphabet, omitted padding, and base64 written with a compatibility character or an invisible character, when the bytes are UTF-8 text; null for anything else. */
export function decodedBlob(value: string): string | null {
  const folded = hasNonAscii(value) ? comparableText(value) : value;
  let compact = folded.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (compact.length < 8) return null;
  if (!compact.includes("=")) {
    const rest = compact.length % 4;
    if (rest === 1) return null;
    if (rest > 0) compact += "=".repeat(4 - rest);
  }
  if (compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null;
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

/** Includes text stored in a base64 blob (URL-safe, unpadded, or written with a compatibility or invisible character), including when that blob is a list or an object, including an object in that list and an object inside that object, and an object inside that blob object, including an object inside that one, and in a list in that blob object, including a list in that list, including a list in that one, including a list in that one as well, including a list beyond that, including one list past that, including one more list past that, including a further list past that, including one list further past that, including one more list further past that, including a further list further past that, including one list beyond that further list, including one more list beyond that further list, including a further list beyond that further list, including one list further beyond that further list, including one more list further beyond that further list, including a further list further beyond that further list, including one list past that further beyond list, including one more list past that further beyond list, including a further list past that further beyond list, in image and audio data, including when that data is a list or an object, including an object in that list and an object inside that object, and an object inside that data object, including an object inside that one, and in a list in that data object, including a list in that list, including a list in that one, including a list in that one as well, including a list beyond that, including one list past that, including one more list past that, including a further list past that, including one list further past that, including one more list further past that, including a further list further past that, including one list beyond that further list, including one more list beyond that further list, including a further list beyond that further list, including one list further beyond that further list, including one more list further beyond that further list, including a further list further beyond that further list, including one list past that further beyond list, including one more list past that further beyond list, and in object keys. */
export function collectText(value: unknown): string[] {
  const out: string[] = [];
  collectStrings(value, out, false);
  return out;
}

function collectStrings(value: unknown, out: string[], decode: boolean, decodeItems = false, decodeNested = false, extra = false, objectLists = false, nestedLists = false, deeperLists = 0): void {
  if (typeof value === "string") {
    out.push(value);
    if (decode) {
      const text = decodedBlob(value);
      if (text !== null) out.push(text);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === "string") collectStrings(item, out, decode, decodeItems, decodeNested, extra, false, false, 0);
      else if (Array.isArray(item)) {
        const oneMore = objectLists && nestedLists;
        const deeperMore = objectLists && deeperLists > 0 && !nestedLists;
        const nextDeeper = oneMore ? deeperLists : (deeperMore ? deeperLists - 1 : 0);
        collectStrings(item, out, oneMore || deeperMore ? true : (objectLists ? false : decode), decodeItems, decodeNested, extra, oneMore || deeperMore, false, nextDeeper);
      } else collectStrings(item, out, decodeItems, false, decodeNested, extra, false, false, 0);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      const objectValue = v !== null && typeof v === "object" && !Array.isArray(v);
      const inDecodedList = (key === "data" || key === "blob") && Array.isArray(v);
      const inDecodedObject = (key === "data" || key === "blob") && objectValue;
      const nestedObject = decodeNested && objectValue;
      const listed = objectLists && Array.isArray(v);
      const decodedObject = (key === "blob" || key === "data") && objectValue;
      const nextDeeper = (key === "blob" && objectValue) ? 18 : (decodedObject ? 17 : (listed ? deeperLists : 0));
      const child = key === "data" || key === "blob" || ((decode || decodeNested) && typeof v === "string") || nestedObject || listed;
      collectStrings(v, out, child, inDecodedList, inDecodedList || inDecodedObject || (extra && nestedObject), inDecodedObject, decodedObject || listed, decodedObject || (listed && nestedLists), nextDeeper);
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

/** Scan every string in a tool definition (description, schema descriptions, defaults, enums), including text folded out of a lookalike form. */
export function scanTool(tool: unknown): Finding[] {
  const text = collectText(tool).flatMap(matchForms).join("\n");
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

/** Scan the text a tool returned for instructions aimed at the model, including text folded out of a lookalike form. */
export function scanResult(result: unknown): Finding[] {
  const text = collectText(result).flatMap(matchForms).join("\n").slice(0, 2_000_000);
  const findings: Finding[] = [];
  for (const check of RESULT_CHECKS) {
    if (check.pattern.test(text)) findings.push({ id: check.id, message: check.message });
  }
  return findings;
}
