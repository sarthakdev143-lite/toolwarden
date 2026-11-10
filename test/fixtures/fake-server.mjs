// A minimal MCP server for tests. It re-reads its tool list from the JSON file
// named in FAKE_TOOLS_FILE on every tools/list, so a test can change a tool
// between sessions. Every tools/call it actually receives is appended to
// FAKE_CALLS_FILE, which lets tests prove a blocked call never arrived.
import { appendFileSync, readFileSync } from "node:fs";

const toolsFile = process.env.FAKE_TOOLS_FILE;
const callsFile = process.env.FAKE_CALLS_FILE;

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  let idx;
  while ((idx = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (line) handle(JSON.parse(line));
  }
});
process.stdin.on("end", () => process.exit(0));

function handle(msg) {
  if (msg.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: { listChanged: true } },
        serverInfo: { name: "fake", version: "1.0.0" },
      },
    });
  } else if (msg.method === "tools/list") {
    const tools = JSON.parse(readFileSync(toolsFile, "utf8"));
    send({ jsonrpc: "2.0", id: msg.id, result: { tools } });
  } else if (msg.method === "tools/call") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify(msg.params) + "\n");
    send({
      jsonrpc: "2.0",
      id: msg.id,
      // A test can choose the tool's output by passing an "echo" argument.
      result: { content: [{ type: "text", text: msg.params.arguments?.echo ?? "ran " + msg.params.name }], isError: false },
    });
  } else if (msg.id !== undefined) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  }
}
