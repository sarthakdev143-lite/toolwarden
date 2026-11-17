/**
 * Cheap heuristics for instructions hidden inside a tool definition.
 *
 * These checks return findings. The firewall does not pin a first definition
 * that has one, because that definition is already talking to the model.
 * A sentence that merely looks similar can still match, so a person reviews it.
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

/** Letters that look like ASCII but are not folded by NFKC. */
const CONFUSABLES = new Map<number, string>([
  [0x0430, "a"], [0x0410, "A"], [0x0435, "e"], [0x0415, "E"], [0x043e, "o"], [0x041e, "O"],
  [0x0440, "p"], [0x0420, "P"], [0x0441, "c"], [0x0421, "C"], [0x0443, "y"], [0x0423, "Y"],
  [0x0445, "x"], [0x0425, "X"], [0x0456, "i"], [0x0406, "I"], [0x0458, "j"], [0x0408, "J"],
  [0x0455, "s"], [0x0405, "S"], [0x04bb, "h"], [0x04ba, "H"], [0x0454, "e"], [0x0404, "E"],
  [0x0501, "d"], [0x0500, "D"], [0x0261, "g"], [0x04cf, "i"], [0x0131, "i"],
  [0x03bf, "o"], [0x039f, "O"], [0x03b9, "i"], [0x0399, "I"], [0x03ba, "k"], [0x039a, "K"],
  [0x03c4, "t"], [0x03a4, "T"], [0x03c7, "x"], [0x03a7, "X"], [0x03c1, "p"], [0x03a1, "P"],
]);

const NAMED_ENTITIES: Record<string, string> = {
  lt: "<", gt: ">", amp: "&", quot: '"', apos: "'", nbsp: " ",
};

function foldConfusables(value: string): string | null {
  if (!hasNonAscii(value)) return null;
  let changed = false;
  let out = "";
  for (const ch of value) {
    const mapped = CONFUSABLES.get(ch.codePointAt(0)!);
    if (mapped !== undefined) {
      changed = true;
      out += mapped;
    } else out += ch;
  }
  return changed ? out : null;
}

/** One layer of HTML character references. Named references cover the characters used to disguise a tag. */
function htmlDecoded(value: string): string | null {
  if (!value.includes("&")) return null;
  let changed = false;
  const decoded = value.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);/g, (all, body: string) => {
    if (body.charCodeAt(0) === 35) {
      const hex = body.charCodeAt(1) === 120 || body.charCodeAt(1) === 88;
      const cp = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
      if (!Number.isInteger(cp) || cp < 0 || cp > 0x10ffff) return all;
      changed = true;
      return String.fromCodePoint(cp);
    }
    const named = NAMED_ENTITIES[body];
    if (named === undefined) return all;
    changed = true;
    return named;
  });
  return changed ? decoded : null;
}

/** One layer of a literal `\uXXXX` or `\xNN` escape that JSON did not already decode. */
function escapesDecoded(value: string): string | null {
  if (!/\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})/.test(value)) return null;
  let changed = false;
  const decoded = value.replace(/\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g, (all, u: string | undefined, x: string | undefined) => {
    const cp = Number.parseInt((u ?? x)!, 16);
    if (!Number.isInteger(cp) || cp > 0x10ffff) return all;
    changed = true;
    return String.fromCodePoint(cp);
  });
  return changed ? decoded : null;
}

/**
 * Join a token that was split into single letters. A separator inside a longer
 * word, such as the underscore in a real token, stays put.
 */
function unsplit(value: string): string | null {
  const joinSingles = (body: string, separators: RegExp) =>
    /^(?:[0-9A-Za-z].)+[0-9A-Za-z]$/.test(body.replace(separators, ".")) ? body.replace(separators, "") : body;
  const dotted = value.replace(
    /(^|[^0-9A-Za-z])((?:[0-9A-Za-z][._\-\u00b7\u2024\u2219]){2,}[0-9A-Za-z])(?=[^0-9A-Za-z]|$)/g,
    (_all, lead: string, body: string) => lead + joinSingles(body, /[._\-\u00b7\u2024\u2219]/g),
  );
  const spaced = dotted.replace(
    /(^|[^0-9A-Za-z])((?:[0-9A-Za-z][ \t]){2,}[0-9A-Za-z])(?=[^0-9A-Za-z]|$)/g,
    (_all, lead: string, body: string) => lead + joinSingles(body, /[ \t]/g),
  );
  return spaced === value ? null : spaced;
}

/**
 * The string itself, plus the same string with one disguise undone: percent-encoding,
 * an HTML character reference, a slash-u or slash-x escape, compatibility or invisible
 * characters, look-alike letters, or separators inserted into a token. Each result is
 * folded again, up to a fixed budget, so those disguises can be stacked once.
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
  for (let i = 0; i < out.length && i < 32; i++) {
    const s = out[i];
    if (s === undefined) continue;
    const decoded = percentDecoded(s);
    if (decoded !== null) add(decoded);
    if (hasNonAscii(s)) {
      const folded = comparableText(s);
      if (folded !== s) add(folded);
    }
    const html = htmlDecoded(s);
    if (html !== null) add(html);
    const escapes = escapesDecoded(s);
    if (escapes !== null) add(escapes);
    const lookalikes = foldConfusables(s);
    if (lookalikes !== null) add(lookalikes);
    const joined = unsplit(s);
    if (joined !== null) add(joined);
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

/** Includes text stored in a base64 blob (URL-safe, unpadded, or written with a compatibility or invisible character), including when that blob, or image or audio data, is nested in a list or object, and in object keys. */
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
    const run: string[] = [];
    const flushRun = () => {
      if (run.length >= 2 && run.every((part) => part.length <= 24)) {
        const joined = run.join("");
        if (joined.length <= 100_000) {
          out.push(joined);
          if (decode) {
            const text = decodedBlob(joined);
            if (text !== null) out.push(text);
          }
        }
      }
      run.length = 0;
    };
    for (const item of value) {
      if (typeof item === "string") run.push(item);
      else flushRun();
      if (typeof item === "string") collectStrings(item, out, decode, decodeItems, decodeNested, extra, false, false, 0);
      else if (Array.isArray(item)) {
        const oneMore = objectLists && nestedLists;
        const deeperMore = objectLists && deeperLists > 0 && !nestedLists;
        const nextDeeper = oneMore ? deeperLists : (deeperMore ? deeperLists - 1 : 0);
        collectStrings(item, out, oneMore || deeperMore ? true : (objectLists ? false : decode), decodeItems, decodeNested, extra, oneMore || deeperMore, false, nextDeeper);
      } else collectStrings(item, out, decodeItems, false, decodeNested, extra, false, false, 0);
    }
    flushRun();
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
      const nextDeeper = decodedObject ? 166 : (listed ? deeperLists : 0);
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
