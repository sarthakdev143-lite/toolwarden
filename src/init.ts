import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { slug } from "./pins.js";

/**
 * Find the MCP servers configured on this machine and wrap them with toolwarden.
 *
 * MCP clients keep their server lists in JSON files. Wrapping a server means
 * rewriting its entry so the client starts toolwarden, which starts the server.
 */

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

export interface ConfigLocation {
  client: string;
  file: string;
}

/** Where well-known MCP clients keep their configuration. */
export function knownConfigLocations(cwd: string): ConfigLocation[] {
  const home = homedir();
  const os = platform();
  const appData =
    os === "win32"
      ? (process.env.APPDATA ?? join(home, "AppData", "Roaming"))
      : os === "darwin"
        ? join(home, "Library", "Application Support")
        : (process.env.XDG_CONFIG_HOME ?? join(home, ".config"));

  return [
    { client: "Claude Desktop", file: join(appData, "Claude", "claude_desktop_config.json") },
    { client: "Claude Code", file: join(home, ".claude.json") },
    { client: "Cursor", file: join(home, ".cursor", "mcp.json") },
    { client: "Windsurf", file: join(home, ".codeium", "windsurf", "mcp_config.json") },
    { client: "VS Code", file: join(appData, "Code", "User", "mcp.json") },
    { client: "Gemini CLI", file: join(home, ".gemini", "settings.json") },
    { client: "Project (.mcp.json)", file: join(cwd, ".mcp.json") },
    { client: "Project (Cursor)", file: join(cwd, ".cursor", "mcp.json") },
    { client: "Project (VS Code)", file: join(cwd, ".vscode", "mcp.json") },
  ];
}

export type ServerKind = "local" | "wrapped" | "remote" | "unknown";

export interface FoundServer {
  client: string;
  file: string;
  /** Keys leading to the server map inside the file, e.g. ["projects", "/home/me/app", "mcpServers"]. */
  path: string[];
  name: string;
  kind: ServerKind;
  /** The original command line, for display. */
  commandLine: string;
}

export interface ScannedFile {
  client: string;
  file: string;
  error?: string;
  servers: FoundServer[];
}

function findServerMaps(obj: Json, file: string, path: string[], depth: number, out: { path: string[]; map: Json }[]): void {
  for (const [key, value] of Object.entries(obj)) {
    if (!isObject(value)) continue;
    const isMap = key === "mcpServers" || (key === "servers" && file.endsWith("mcp.json") && depth === 0);
    if (isMap) out.push({ path: [...path, key], map: value });
    else if (depth < 3) findServerMaps(value, file, [...path, key], depth + 1, out);
  }
}

function argsOf(entry: Json): string[] {
  return Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [];
}

export function isWrapped(entry: Json): boolean {
  const args = argsOf(entry);
  const sep = args.indexOf("--");
  if (sep === -1 || !args.slice(0, sep).includes("run")) return false;
  const head = [typeof entry.command === "string" ? entry.command : "", ...args.slice(0, sep)];
  return head.some((part) => /toolwarden/i.test(part));
}

function classify(entry: unknown): { kind: ServerKind; commandLine: string } {
  if (!isObject(entry)) return { kind: "unknown", commandLine: "" };
  if (typeof entry.command === "string") {
    const commandLine = [entry.command, ...argsOf(entry)].join(" ");
    return { kind: isWrapped(entry) ? "wrapped" : "local", commandLine };
  }
  const url = entry.url ?? entry.serverUrl ?? entry.httpUrl;
  if (typeof url === "string") return { kind: "remote", commandLine: url };
  return { kind: "unknown", commandLine: "" };
}

export function scanFile(loc: ConfigLocation): ScannedFile | null {
  if (!existsSync(loc.file)) return null;
  let root: unknown;
  try {
    root = JSON.parse(readFileSync(loc.file, "utf8"));
  } catch {
    return { ...loc, error: "could not be read as JSON (it may contain comments); skipped", servers: [] };
  }
  if (!isObject(root)) return { ...loc, servers: [] };
  const maps: { path: string[]; map: Json }[] = [];
  findServerMaps(root, loc.file, [], 0, maps);
  const servers: FoundServer[] = [];
  for (const { path, map } of maps) {
    for (const [name, entry] of Object.entries(map)) {
      servers.push({ client: loc.client, file: loc.file, path, name, ...classify(entry) });
    }
  }
  return { ...loc, servers };
}

export function scanAll(locations: ConfigLocation[]): ScannedFile[] {
  const seen = new Set<string>();
  const out: ScannedFile[] = [];
  for (const loc of locations) {
    const file = resolve(loc.file);
    if (seen.has(file)) continue;
    seen.add(file);
    const scanned = scanFile({ ...loc, file });
    if (scanned) out.push(scanned);
  }
  return out;
}

function detectIndent(text: string): string | number {
  const m = /^[ \t]+(?=")/m.exec(text);
  return m ? m[0] : 2;
}

function getAt(root: Json, path: string[]): Json | null {
  let cur: unknown = root;
  for (const key of path) {
    if (!isObject(cur)) return null;
    cur = cur[key];
  }
  return isObject(cur) ? cur : null;
}

export interface RewriteResult {
  file: string;
  changed: string[];
  backup: string | null;
}

/**
 * Wrap (or unwrap) the local servers in one config file.
 *
 * `launcher` is the command that starts toolwarden, e.g. ["/usr/bin/node", "/path/to/cli.js"].
 * `nameFor` picks the toolwarden name for a server, so the caller can keep names unique.
 */
export function rewriteFile(
  file: string,
  action: "wrap" | "unwrap",
  launcher: string[],
  nameFor: (server: { name: string; commandLine: string }) => string,
): RewriteResult {
  const text = readFileSync(file, "utf8");
  const root = JSON.parse(text) as Json;
  const maps: { path: string[]; map: Json }[] = [];
  findServerMaps(root, file, [], 0, maps);
  const changed: string[] = [];

  for (const { path } of maps) {
    const map = getAt(root, path);
    if (!map) continue;
    for (const [name, entry] of Object.entries(map)) {
      if (!isObject(entry) || typeof entry.command !== "string") continue;
      const args = argsOf(entry);
      if (action === "wrap" && !isWrapped(entry)) {
        const commandLine = [entry.command, ...args].join(" ");
        const [launchCommand, ...launchArgs] = launcher as [string, ...string[]];
        map[name] = {
          ...entry,
          command: launchCommand,
          args: [...launchArgs, "run", "--name", nameFor({ name, commandLine }), "--", entry.command, ...args],
        };
        changed.push(name);
      } else if (action === "unwrap" && isWrapped(entry)) {
        const sep = args.indexOf("--");
        const [originalCommand, ...originalArgs] = args.slice(sep + 1);
        if (originalCommand === undefined) continue;
        map[name] = { ...entry, command: originalCommand, args: originalArgs };
        changed.push(name);
      }
    }
  }

  if (changed.length === 0) return { file, changed, backup: null };

  // Keep the first backup: it is the file as it was before toolwarden touched it.
  const backup = file + ".toolwarden-backup";
  if (!existsSync(backup)) copyFileSync(file, backup);
  writeFileSync(file, JSON.stringify(root, null, detectIndent(text)) + (text.endsWith("\n") ? "\n" : ""));
  return { file, changed, backup };
}

/**
 * Give each distinct server its own toolwarden name. Two clients that run the
 * same command under the same name share pins; the same name with a different
 * command gets a suffix so their pins do not collide.
 */
export function makeNamer(): (server: { name: string; commandLine: string }, client: string) => string {
  const taken = new Map<string, string>();
  return (server, client) => {
    const base = slug(server.name);
    const owner = taken.get(base);
    if (owner === undefined || owner === server.commandLine) {
      taken.set(base, server.commandLine);
      return base;
    }
    let candidate = slug(`${server.name}-${client}`);
    let n = 2;
    while (taken.has(candidate) && taken.get(candidate) !== server.commandLine) {
      candidate = slug(`${server.name}-${client}-${n++}`);
    }
    taken.set(candidate, server.commandLine);
    return candidate;
  };
}
