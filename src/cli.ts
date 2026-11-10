#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { AuditLog } from "./audit.js";
import { startDashboard } from "./dashboard.js";
import { Firewall, type Mode, type ResultMode } from "./firewall.js";
import { FlowTracker } from "./flow.js";
import { startHttpProxy } from "./http.js";
import { knownConfigLocations, makeNamer, rewriteFile, scanAll, type ScannedFile } from "./init.js";
import { approve, listServers, loadPins, savePins, slug, type PinFile } from "./pins.js";
import { loadPolicy, type Policy } from "./policy.js";
import { runProxy } from "./proxy.js";

const VERSION = "0.2.0";

const HELP = `toolwarden ${VERSION} — a runtime firewall for MCP servers

Usage:
  toolwarden init [--dry-run] [--yes] [--undo]   Find the MCP servers on this machine and protect them
  toolwarden run [options] -- <server command>   Run a local MCP server behind the firewall
  toolwarden http [options] --target <url>       Run a local proxy in front of a remote MCP server
  toolwarden status [server]                     Show approved tools and anything waiting for review
  toolwarden approve <server> [tool...]          Approve changed or new tools (all pending if none named)
  toolwarden log [-n <count>]                    Show recent audit log entries
  toolwarden dashboard [--port 7878]             Open a local web page for reviews and the log

Options for "run" and "http":
  --name <id>          Name for this server (default: derived from the command or URL)
  --mode <block|warn>  block (default) stops bad calls; warn only reports them
  --results <mode>     What to do when tool output looks like instructions:
                       annotate (default), warn, block, or off
  --policy <file>      Policy file with extra rules (default: <state>/policy.json if present)
  --no-default-rules   Turn off the built-in credential-path rules
  --no-flow            Turn off tracking of data moving between servers
  --state <dir>        Where pins and logs live (default: ~/.toolwarden, or $TOOLWARDEN_HOME)

Options for "http":
  --target <url>       The remote MCP server's URL
  --port <number>      Local port to listen on (default 8787)

Options for "init":
  --dry-run            Only list what was found
  --yes                Do not ask before changing files
  --undo               Remove toolwarden from the config files again
  --config <file>      Only look at this config file
`;

function fail(message: string): never {
  process.stderr.write(`toolwarden: ${message}\n`);
  process.exit(2);
}

function defaultStateDir(): string {
  return process.env.TOOLWARDEN_HOME ?? join(homedir(), ".toolwarden");
}

/** Pull "--flag value" style options out of an argument list. */
function parseOptions(
  argv: string[],
  valueFlags: string[],
  boolFlags: string[],
): { values: Record<string, string>; bools: Set<string>; rest: string[] } {
  const values: Record<string, string> = {};
  const bools = new Set<string>();
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (valueFlags.includes(a)) {
      const v = argv[++i];
      if (v === undefined) fail(`${a} needs a value`);
      values[a] = v;
    } else if (boolFlags.includes(a)) {
      bools.add(a);
    } else if (a.startsWith("-") && a.length > 1) {
      fail(`unknown option ${a}`);
    } else {
      rest.push(a);
    }
  }
  return { values, bools, rest };
}

function defaultServerName(command: string, args: string[]): string {
  const full = [command, ...args].join(" ");
  const digest = createHash("sha256").update(full).digest("hex").slice(0, 8);
  // Prefer the most descriptive token: the last argument that looks like a package or script name.
  const descriptive = [...args].reverse().find((a) => !a.startsWith("-") && /[a-zA-Z]/.test(a) && !a.startsWith("/"));
  return slug(basename(descriptive ?? command)).slice(0, 40) + "-" + digest;
}

const SHARED_VALUE_FLAGS = ["--name", "--mode", "--results", "--policy", "--state"];
const SHARED_BOOL_FLAGS = ["--no-default-rules", "--no-flow"];

/** Build a firewall from the options that "run" and "http" share. */
function buildFirewall(
  values: Record<string, string>,
  bools: Set<string>,
  fallbackName: string,
  commandLabel: string,
): Firewall {
  const mode = (values["--mode"] ?? "block") as Mode;
  if (mode !== "block" && mode !== "warn") fail('--mode must be "block" or "warn"');
  const results = (values["--results"] ?? "annotate") as ResultMode;
  if (!["off", "warn", "annotate", "block"].includes(results)) {
    fail("--results must be one of: annotate, warn, block, off");
  }

  const stateDir = values["--state"] ?? defaultStateDir();
  const server = values["--name"] ? slug(values["--name"]) : fallbackName;

  const defaultPolicyPath = join(stateDir, "policy.json");
  const policyPath = values["--policy"] ?? (existsSync(defaultPolicyPath) ? defaultPolicyPath : null);
  let policy: Policy;
  try {
    policy = loadPolicy(policyPath, !bools.has("--no-default-rules"));
  } catch (err) {
    fail((err as Error).message);
  }

  // stdout belongs to the MCP protocol, so everything for humans goes to stderr.
  const audit = new AuditLog(stateDir, server, (line) => process.stderr.write(line + "\n"));
  return new Firewall({
    server,
    command: commandLabel,
    stateDir,
    mode,
    policy,
    audit,
    results,
    flow: bools.has("--no-flow") ? null : new FlowTracker(stateDir, server),
  });
}

async function cmdRun(argv: string[]): Promise<number> {
  const sep = argv.indexOf("--");
  if (sep === -1 || sep === argv.length - 1) {
    fail('"run" needs a server command after "--". Example: toolwarden run -- npx some-mcp-server');
  }
  const { values, bools, rest } = parseOptions(argv.slice(0, sep), SHARED_VALUE_FLAGS, SHARED_BOOL_FLAGS);
  if (rest.length > 0) fail(`unexpected argument "${rest[0]}" before "--"`);
  const [command, ...args] = argv.slice(sep + 1) as [string, ...string[]];
  const firewall = buildFirewall(values, bools, defaultServerName(command, args), [command, ...args].join(" "));
  return runProxy(firewall, command, args);
}

async function cmdHttp(argv: string[]): Promise<number> {
  const { values, bools, rest } = parseOptions(argv, [...SHARED_VALUE_FLAGS, "--target", "--port"], SHARED_BOOL_FLAGS);
  if (rest.length > 0) fail(`unexpected argument "${rest[0]}"`);
  const target = values["--target"];
  if (!target) fail('"http" needs --target <url>. Example: toolwarden http --target https://example.com/mcp');
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    fail(`--target is not a valid URL: ${target}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") fail("--target must start with http:// or https://");
  const port = Number.parseInt(values["--port"] ?? "8787", 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail("--port must be a number between 0 and 65535");

  const digest = createHash("sha256").update(target).digest("hex").slice(0, 8);
  const firewall = buildFirewall(values, bools, slug(url.hostname) + "-" + digest, target);
  let server;
  try {
    server = await startHttpProxy(firewall, { target, port });
  } catch (err) {
    fail(`could not listen on port ${port}: ${(err as Error).message}`);
  }
  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : port;
  process.stderr.write(
    `[toolwarden] protecting ${target}\n` +
      `[toolwarden] point your MCP client at: http://127.0.0.1:${actualPort}/\n`,
  );
  return new Promise((resolveExit) => {
    const stop = () => server.close(() => resolveExit(0));
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
}

function describe(def: unknown): { description: string; schema: string } {
  const d = (def ?? {}) as Record<string, unknown>;
  return {
    description: typeof d.description === "string" ? d.description : "",
    schema: JSON.stringify(d.inputSchema ?? null),
  };
}

function printServer(pins: PinFile): void {
  const pinned = Object.keys(pins.tools).sort();
  const pending = Object.keys(pins.pending).sort();
  console.log(`\n${pins.server}`);
  console.log(`  command: ${pins.command}`);
  console.log(`  approved tools (${pinned.length}): ${pinned.join(", ") || "none"}`);
  if (pending.length === 0) {
    console.log("  waiting for review: nothing");
    return;
  }
  console.log(`  waiting for review (${pending.length}):`);
  for (const name of pending) {
    const p = pins.pending[name]!;
    const next = describe(p.definition);
    if (p.kind === "new") {
      console.log(`\n  + ${name}  (new tool, first seen ${p.seenAt})`);
      console.log(`      description: ${next.description || "(none)"}`);
      continue;
    }
    const prev = describe(pins.tools[name]?.definition);
    console.log(`\n  ~ ${name}  (changed, first seen ${p.seenAt})`);
    if (prev.description !== next.description) {
      console.log(`      - description: ${prev.description || "(none)"}`);
      console.log(`      + description: ${next.description || "(none)"}`);
    }
    if (prev.schema !== next.schema) {
      console.log(`      - input schema: ${prev.schema}`);
      console.log(`      + input schema: ${next.schema}`);
    }
    if (prev.description === next.description && prev.schema === next.schema) {
      console.log("      another field of the definition changed (title, annotations or output schema)");
    }
  }
  console.log(`\n  To approve: toolwarden approve ${pins.server} [tool...]`);
}

function cmdStatus(argv: string[]): number {
  const { values, rest } = parseOptions(argv, ["--state"], []);
  const stateDir = values["--state"] ?? defaultStateDir();
  const servers = rest.length > 0 ? rest.map(slug) : listServers(stateDir);
  if (servers.length === 0) {
    console.log('No servers pinned yet. Run "toolwarden init" to protect the MCP servers on this machine.');
    return 0;
  }
  let pendingTotal = 0;
  for (const s of servers) {
    const pins = loadPins(stateDir, s);
    if (!pins) {
      console.log(`\n${s}\n  not found`);
      continue;
    }
    pendingTotal += Object.keys(pins.pending).length;
    printServer(pins);
  }
  console.log("");
  // A non-zero exit lets scripts and CI notice unreviewed changes.
  return pendingTotal > 0 ? 1 : 0;
}

function cmdApprove(argv: string[]): number {
  const { values, rest } = parseOptions(argv, ["--state"], []);
  const stateDir = values["--state"] ?? defaultStateDir();
  const [serverArg, ...tools] = rest;
  if (!serverArg) fail("approve needs a server name. See: toolwarden status");
  const pins = loadPins(stateDir, slug(serverArg));
  if (!pins) fail(`no pinned server named "${serverArg}". See: toolwarden status`);
  const unknown = tools.filter((t) => !pins.pending[t]);
  if (unknown.length > 0) fail(`nothing waiting for review under: ${unknown.join(", ")}`);
  const approved = approve(pins, tools);
  if (approved.length === 0) {
    console.log("Nothing was waiting for review.");
    return 0;
  }
  savePins(stateDir, pins);
  console.log(`Approved on ${pins.server}: ${approved.join(", ")}`);
  console.log("Restart the MCP client (or reconnect the server) for the change to take effect.");
  return 0;
}

function cmdLog(argv: string[]): number {
  const { values } = parseOptions(argv, ["--state", "-n"], []);
  const stateDir = values["--state"] ?? defaultStateDir();
  const count = Number.parseInt(values["-n"] ?? "30", 10);
  if (!Number.isFinite(count) || count <= 0) fail("-n needs a positive number");
  const path = join(stateDir, "audit.log");
  if (!existsSync(path)) {
    console.log("No audit log yet.");
    return 0;
  }
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean).slice(-count);
  for (const line of lines) {
    try {
      const r = JSON.parse(line) as Record<string, unknown>;
      const { ts, server, event, tool, ...detail } = r;
      const extra = Object.keys(detail).length > 0 ? " " + JSON.stringify(detail) : "";
      console.log(`${ts}  ${String(event).padEnd(18)} ${server}${tool ? " / " + tool : ""}${extra}`);
    } catch {
      console.log(line);
    }
  }
  return 0;
}

function printScan(files: ScannedFile[]): { local: number; wrapped: number; remote: number } {
  const totals = { local: 0, wrapped: 0, remote: 0 };
  for (const f of files) {
    console.log(`\n${f.client}  ${f.file}`);
    if (f.error) {
      console.log(`  ${f.error}`);
      continue;
    }
    if (f.servers.length === 0) {
      console.log("  no MCP servers configured");
      continue;
    }
    for (const s of f.servers) {
      const label =
        s.kind === "local"
          ? "not protected"
          : s.kind === "wrapped"
            ? "protected"
            : s.kind === "remote"
              ? "remote (use: toolwarden http)"
              : "unrecognized entry";
      if (s.kind === "local") totals.local++;
      else if (s.kind === "wrapped") totals.wrapped++;
      else if (s.kind === "remote") totals.remote++;
      const where = s.path.length > 1 ? `  [${s.path.slice(0, -1).join(" > ")}]` : "";
      console.log(`  ${s.name.padEnd(22)} ${label.padEnd(30)} ${s.commandLine.slice(0, 90)}${where}`);
    }
  }
  console.log("");
  return totals;
}

async function cmdInit(argv: string[]): Promise<number> {
  const { values, bools, rest } = parseOptions(argv, ["--config"], ["--dry-run", "--yes", "--undo"]);
  if (rest.length > 0) fail(`unexpected argument "${rest[0]}"`);
  const locations = values["--config"]
    ? [{ client: "Config", file: resolve(values["--config"]) }]
    : knownConfigLocations(process.cwd());
  if (values["--config"] && !existsSync(locations[0]!.file)) fail(`config file not found: ${values["--config"]}`);

  const files = scanAll(locations);
  if (files.length === 0) {
    console.log("No MCP client configuration found on this machine.");
    console.log("If yours lives somewhere unusual, pass it with: toolwarden init --config <file>");
    return 0;
  }
  const totals = printScan(files);
  const undo = bools.has("--undo");
  const todo = undo ? totals.wrapped : totals.local;

  if (bools.has("--dry-run")) return 0;
  if (todo === 0) {
    console.log(undo ? "Nothing is wrapped by toolwarden." : "Every local server is already protected.");
    return 0;
  }

  if (!bools.has("--yes")) {
    if (!process.stdin.isTTY) {
      console.log(`Run again with --yes to ${undo ? "remove toolwarden from" : "protect"} ${todo} server(s).`);
      return 0;
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const question = undo
      ? `Remove toolwarden from ${todo} server(s)? [y/N] `
      : `Protect ${todo} server(s)? Each config file is backed up first. [y/N] `;
    const answer = (await rl.question(question)).trim().toLowerCase();
    rl.close();
    if (answer !== "y" && answer !== "yes") {
      console.log("Nothing changed.");
      return 0;
    }
  }

  // Start toolwarden through this exact Node binary and script, so it works
  // from GUI apps whose PATH differs from the terminal's.
  const launcher = [process.execPath, fileURLToPath(import.meta.url)];
  const namer = makeNamer();
  let changedTotal = 0;
  for (const f of files) {
    if (f.error) continue;
    const needsWork = f.servers.some((s) => s.kind === (undo ? "wrapped" : "local"));
    if (!needsWork) continue;
    try {
      const result = rewriteFile(f.file, undo ? "unwrap" : "wrap", launcher, (s) => namer(s, f.client));
      changedTotal += result.changed.length;
      console.log(`${undo ? "Restored" : "Protected"} in ${f.file}: ${result.changed.join(", ")}`);
      if (result.backup) console.log(`  backup: ${result.backup}`);
    } catch (err) {
      console.log(`Could not update ${f.file}: ${(err as Error).message}`);
    }
  }
  if (changedTotal > 0) {
    console.log("\nRestart your MCP clients for this to take effect.");
    if (!undo) console.log('Then run "toolwarden dashboard" to watch what your servers do.');
  }
  return 0;
}

async function cmdDashboard(argv: string[]): Promise<number> {
  const { values } = parseOptions(argv, ["--state", "--port"], []);
  const stateDir = values["--state"] ?? defaultStateDir();
  const port = Number.parseInt(values["--port"] ?? "7878", 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail("--port must be a number between 0 and 65535");
  let dashboard;
  try {
    dashboard = await startDashboard(stateDir, port);
  } catch (err) {
    fail(`could not start the dashboard on port ${port}: ${(err as Error).message}`);
  }
  console.log(`toolwarden dashboard: ${dashboard.url}`);
  console.log("The link carries an access token. Keep it to yourself. Press Ctrl+C to stop.");
  return new Promise((resolveExit) => {
    const stop = () => dashboard.server.close(() => resolveExit(0));
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "run":
      process.exit(await cmdRun(rest));
    case "http":
      process.exit(await cmdHttp(rest));
    case "init":
      process.exit(await cmdInit(rest));
    case "dashboard":
      process.exit(await cmdDashboard(rest));
    case "status":
      process.exit(cmdStatus(rest));
    case "approve":
      process.exit(cmdApprove(rest));
    case "log":
      process.exit(cmdLog(rest));
    case "--version":
    case "-v":
      console.log(VERSION);
      process.exit(0);
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      process.exit(0);
    default:
      fail(`unknown command "${command}". Run "toolwarden help".`);
  }
}

void main();
