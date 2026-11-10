import { createHash } from "node:crypto";

/**
 * Serialize a JSON value with object keys sorted, so two definitions that
 * differ only in key order produce the same string (and the same hash).
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}

/** SHA-256 over the canonical form of a tool definition. */
export function hashTool(tool: unknown): string {
  return createHash("sha256").update(canonicalize(tool)).digest("hex");
}
