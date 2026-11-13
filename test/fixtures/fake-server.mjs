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

function listResult(cursor) {
  const raw = JSON.parse(readFileSync(toolsFile, "utf8"));
  if (Array.isArray(raw)) {
    const result = { tools: raw };
    if (process.env.FAKE_NEXT_CURSOR) result.nextCursor = process.env.FAKE_NEXT_CURSOR;
    return result;
  }
  const pages = Array.isArray(raw?.pages) ? raw.pages : [];
  const index = typeof cursor === "string" && cursor !== "" ? Number.parseInt(cursor, 10) : 0;
  const tools = Number.isInteger(index) && Array.isArray(pages[index]) ? pages[index] : [];
  const result = { tools };
  if (Number.isInteger(index) && index + 1 < pages.length) result.nextCursor = String(index + 1);
  return result;
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
    const result = {
      protocolVersion: "2025-06-18",
      capabilities: { tools: { listChanged: true } },
      serverInfo:
        msg.params?.serverInfo && typeof msg.params.serverInfo === "object"
          ? msg.params.serverInfo
          : { name: "fake", version: "1.0.0" },
    };
    if (typeof msg.params?.instructions === "string") result.instructions = msg.params.instructions;
    send({ jsonrpc: "2.0", id: msg.id, result });
  } else if (msg.method === "test/sampling") {
    send({ jsonrpc: "2.0", id: 9001, method: "sampling/createMessage", params: msg.params });
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: listResult(msg.params?.cursor) });
  } else if (msg.method === "resources/list") {
    const resources = Array.isArray(msg.params?.resources) ? msg.params.resources : [];
    send({ jsonrpc: "2.0", id: msg.id, result: { resources } });
  } else if (msg.method === "prompts/list") {
    const prompts = Array.isArray(msg.params?.prompts) ? msg.params.prompts : [];
    send({ jsonrpc: "2.0", id: msg.id, result: { prompts } });
  } else if (msg.method === "resources/templates/list") {
    const resourceTemplates = Array.isArray(msg.params?.resourceTemplates) ? msg.params.resourceTemplates : [];
    send({ jsonrpc: "2.0", id: msg.id, result: { resourceTemplates } });
  } else if (msg.method === "resources/read") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
    const uri = typeof msg.params?.uri === "string" ? msg.params.uri : "file://doc";
    const text = typeof msg.params?.text === "string" ? msg.params.text : "a plain document";
    send({ jsonrpc: "2.0", id: msg.id, result: { contents: [{ uri, mimeType: "text/plain", text }] } });
  } else if (msg.method === "prompts/get") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
    const text = typeof msg.params?.text === "string" ? msg.params.text : "a plain prompt";
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: { messages: [{ role: "user", content: { type: "text", text } }] },
    });
  } else if (msg.method === "tools/call") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify(msg.params) + "\n");
    if (typeof msg.params?.arguments?.fail === "string") {
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: msg.params.arguments.fail } });
      return;
    }
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
