import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

export interface PinEntry {
  hash: string;
  definition: unknown;
  pinnedAt: string;
}

export interface PendingEntry {
  hash: string;
  definition: unknown;
  seenAt: string;
  /** "changed": differs from the pinned definition. "new": appeared after the first trusted listing. */
  kind: "changed" | "new";
}

export interface PinFile {
  server: string;
  command: string;
  createdAt: string;
  tools: Record<string, PinEntry>;
  pending: Record<string, PendingEntry>;
}

/** Make a server name safe to use as a file name. */
export function slug(name: string): string {
  const s = name.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return s.length > 0 ? s.slice(0, 80) : "server";
}

function pinsDir(stateDir: string): string {
  return join(stateDir, "pins");
}

function pinPath(stateDir: string, server: string): string {
  return join(pinsDir(stateDir), slug(server) + ".json");
}

export function loadPins(stateDir: string, server: string): PinFile | null {
  const p = pinPath(stateDir, server);
  if (!existsSync(p)) return null;
  const parsed = JSON.parse(readFileSync(p, "utf8")) as PinFile;
  parsed.tools ??= {};
  parsed.pending ??= {};
  return parsed;
}

/** Write atomically (temp file + rename) so a crash never leaves a half-written pin file. */
export function savePins(stateDir: string, pins: PinFile): void {
  mkdirSync(pinsDir(stateDir), { recursive: true, mode: 0o700 });
  const p = pinPath(stateDir, pins.server);
  const tmp = p + "." + process.pid + ".tmp";
  writeFileSync(tmp, JSON.stringify(pins, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, p);
}

export function listServers(stateDir: string): string[] {
  const dir = pinsDir(stateDir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -5))
    .sort();
}

/**
 * Move pending definitions into the pinned set. With no tool names, approves
 * everything pending. Returns the names that were approved.
 */
export function approve(pins: PinFile, toolNames: string[]): string[] {
  const names = toolNames.length > 0 ? toolNames : Object.keys(pins.pending);
  const approved: string[] = [];
  for (const name of names) {
    const pending = pins.pending[name];
    if (!pending) continue;
    pins.tools[name] = {
      hash: pending.hash,
      definition: pending.definition,
      pinnedAt: new Date().toISOString(),
    };
    delete pins.pending[name];
    approved.push(name);
  }
  return approved;
}

export interface ReviewedTool {
  name: string;
  hash: string;
}

/** Pin these definitions only when every hash is still pending. Otherwise pin nothing. */
export function approveReviewed(pins: PinFile, reviews: ReviewedTool[]): { approved: string[]; stale: string[] } {
  const stale = reviews.filter((review) => pins.pending[review.name]?.hash !== review.hash).map((review) => review.name);
  if (stale.length > 0) return { approved: [], stale };
  return { approved: approve(pins, reviews.map((review) => review.name)), stale: [] };
}
