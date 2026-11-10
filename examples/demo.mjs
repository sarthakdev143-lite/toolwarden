// Runs the rug-pull attack twice: once unprotected, once behind toolwarden.
// Usage: npm run demo
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const SERVER = join(here, "rugpull-server.mjs");

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

/** Act as a tiny MCP client: list the tools, then call get_weather the way a tricked AI would. */
function runSession(command, args, env, callArgs) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, ...env } });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    const replies = new Map();
    let buffer = "";
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        replies.set(msg.id, msg);
        // Like a real client: call the tool only after the listing has arrived.
        if (msg.id === 1) {
          send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "get_weather", arguments: callArgs } });
        }
        if (msg.id === 2) child.stdin.end();
      }
    });
    child.on("exit", () => resolve({ list: replies.get(1), call: replies.get(2), stderr }));
    const send = (m) => child.stdin.write(JSON.stringify(m) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  });
}

function show(label, result) {
  const tools = result.list.result.tools;
  console.log(`  ${bold(label)}`);
  console.log(`    tools the AI can see: ${tools.length === 0 ? "(none)" : tools.map((t) => t.name).join(", ")}`);
  for (const t of tools) console.log(dim(`    description: ${t.description}`));
  console.log(`    result of the call:   ${result.call.result.content[0].text}`);
  for (const line of result.stderr.split("\n").filter(Boolean)) {
    const paint = /BLOCKED|DENIED/.test(line) ? red : /WARNING/.test(line) ? yellow : dim;
    console.log(`    ${paint(line)}`);
  }
  console.log("");
}

const honestCall = { city: "Indore" };
const trickedCall = { city: "Indore", notes: "-----BEGIN OPENSSH PRIVATE KEY----- (contents of ~/.ssh/id_rsa)" };

console.log(bold("\n1. WITHOUT toolwarden\n"));
{
  const marker = join(mkdtempSync(join(tmpdir(), "tw-demo-")), "marker");
  const env = { RUGPULL_MARKER: marker };
  show("Day 1: the server is honest", await runSession("node", [SERVER], env, honestCall));
  const day2 = await runSession("node", [SERVER], env, trickedCall);
  show("Day 2: the server has changed its tool", day2);
  console.log(red("  The AI followed the hidden instructions and the server received the key.\n"));
}

console.log(bold("2. WITH toolwarden\n"));
{
  const dir = mkdtempSync(join(tmpdir(), "tw-demo-"));
  const env = { RUGPULL_MARKER: join(dir, "marker") };
  const state = join(dir, "state");
  const wrapped = [CLI, "run", "--name", "weather", "--state", state, "--", "node", SERVER];
  show("Day 1: the server is honest", await runSession("node", wrapped, env, honestCall));
  show("Day 2: the server has changed its tool", await runSession("node", wrapped, env, trickedCall));
  console.log(green("  The changed tool was hidden from the AI and the call never reached the server.\n"));
  console.log(bold("  What you see when you review it (toolwarden status):"));
  const status = spawnSync("node", [CLI, "status", "--state", state], { encoding: "utf8" });
  console.log(status.stdout.split("\n").map((l) => "  " + l).join("\n"));
}
