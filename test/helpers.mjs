import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const CLI = join(here, "..", "dist", "cli.js");
export const FAKE = join(here, "fixtures", "fake-server.mjs");

export const ECHO = {
  name: "echo",
  description: "Return the given text.",
  inputSchema: { type: "object", properties: { echo: { type: "string" } } },
};
export const SEND = {
  name: "send",
  description: "Send a message.",
  inputSchema: { type: "object", properties: { body: { type: "string" } } },
};

/** A fresh sandbox: its own state dir, tool file and call log. */
export function sandbox(tools) {
  const dir = mkdtempSync(join(tmpdir(), "toolwarden-test-"));
  const box = {
    dir,
    state: join(dir, "state"),
    toolsFile: join(dir, "tools.json"),
    callsFile: join(dir, "calls.log"),
    setTools(t) {
      writeFileSync(box.toolsFile, JSON.stringify(t));
    },
    serverCalls() {
      if (!existsSync(box.callsFile)) return [];
      return readFileSync(box.callsFile, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    },
    audit() {
      const p = join(box.state, "audit.log");
      if (!existsSync(p)) return [];
      return readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    },
    cli(...args) {
      return spawnSync("node", [CLI, ...args, "--state", box.state], { encoding: "utf8" });
    },
  };
  box.setTools(tools);
  return box;
}

/** Talk JSON-RPC over a child process's stdio, like an MCP client. */
export function connect(child) {
  let stderr = "";
  child.stderr.on("data", (c) => (stderr += c.toString()));
  const waiting = new Map();
  let buffer = "";
  child.stdout.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    let idx;
    while ((idx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      waiting.get(msg.id)?.(msg);
      waiting.delete(msg.id);
    }
  });
  let nextId = 1;
  return {
    request(method, params) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no reply to ${method} within 5s`)), 5000);
        waiting.set(id, (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });
    },
    async listTools() {
      const res = await this.request("tools/list", {});
      return res.result.tools.map((t) => t.name);
    },
    call(name, args) {
      return this.request("tools/call", { name, arguments: args });
    },
    stderr: () => stderr,
    close() {
      return new Promise((resolve) => {
        child.on("exit", resolve);
        child.stdin.end();
      });
    },
  };
}

/** Start the proxy around the fake server. */
export function session(box, extraArgs = [], name = "fake") {
  const child = spawn(
    "node",
    [CLI, "run", "--name", name, "--state", box.state, ...extraArgs, "--", "node", FAKE],
    {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, FAKE_TOOLS_FILE: box.toolsFile, FAKE_CALLS_FILE: box.callsFile },
    },
  );
  return connect(child);
}

/** Start a long-running CLI command and wait until its output matches a pattern. */
export function startCli(args, pattern, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", [CLI, ...args], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
    let output = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("CLI did not start in time. Output:\n" + output));
    }, 8000);
    const onData = (c) => {
      output += c.toString();
      const m = pattern.exec(output);
      if (m) {
        clearTimeout(timer);
        resolve({
          child,
          match: m,
          output: () => output,
          stop: () => new Promise((done) => (child.on("exit", done), child.kill("SIGTERM"))),
        });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
  });
}
