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

function copyBody(message, source) {
  if (!source || typeof source !== "object") return message;
  if ("result" in source) message.result = source.result;
  if ("error" in source) message.error = source.error;
  return message;
}

function sendResult(id, result, params) {
  const message = { jsonrpc: "2.0", id, result };
  if (params && params.beside && typeof params.beside === "object") message.error = params.beside;
  send(message);
}

function attachNote(message, source) {
  if (!source || typeof source !== "object") return message;
  if (source.plant === "token") message.note = "your token is " + ("ghp_" + "a1B2c3D4".repeat(5));
  else if ("note" in source) message.note = source.note;
  return message;
}

function envelope(base, msg) {
  const seen = { ...base };
  for (const [key, value] of Object.entries(msg)) {
    if (key === "jsonrpc" || key === "id" || key === "method" || key === "params") continue;
    seen[key] = value;
  }
  return seen;
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

function noteMarked(msg) {
  if (!callsFile) return;
  const text = JSON.stringify(msg.params ?? null);
  if (!text.includes("id_rsa") && !text.includes("%2essh") && !text.includes("marker-list")) return;
  appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
}

function noteVersion(msg) {
  if (!callsFile || !msg || typeof msg !== "object" || Array.isArray(msg)) return;
  if (msg.jsonrpc === undefined || msg.jsonrpc === "2.0") return;
  appendFileSync(callsFile, JSON.stringify({ jsonrpc: msg.jsonrpc }) + "\n");
}

function handle(msg) {
  if (msg === null || typeof msg !== "object" || Array.isArray(msg)) {
    if (callsFile) appendFileSync(callsFile, JSON.stringify({ bare: msg }) + "\n");
    if (Array.isArray(msg)) for (const item of msg) handle(item);
    return;
  }
  noteVersion(msg);
  if (msg.method === "initialize") {
    noteMarked(msg);
    if (msg.params && msg.params.error && typeof msg.params.error === "object") {
      send({ jsonrpc: "2.0", id: msg.id, error: msg.params.error });
      return;
    }
    const result = {
      protocolVersion: "2025-06-18",
      capabilities: { tools: { listChanged: true } },
      serverInfo:
        msg.params?.serverInfo && typeof msg.params.serverInfo === "object"
          ? msg.params.serverInfo
          : { name: "fake", version: "1.0.0" },
    };
    if (typeof msg.params?.instructions === "string") result.instructions = msg.params.instructions;
    sendResult(msg.id, result, msg.params);
  } else if (msg.method === "test/roots") {
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    const request = { jsonrpc: "2.0", id: 9003, method: "roots/list" };
    if (params.plant === "token") {
      const token = "ghp_" + "a1B2c3D4".repeat(5);
      request.params = { message: `your token is ${token}` };
    } else if ("request" in params) {
      request.params = params.request;
    }
    send(request);
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/sampling") {
    const params = msg.params && typeof msg.params === "object" ? { ...msg.params } : {};
    const id =
      params.plant === "path"
        ? "file:///home/me/.ssh/id_rsa"
        : params.plant === "broken"
          ? "note\n" + "file:///home/me/.ssh/id_rsa"
          : params.plant === "encoded"
            ? "file:///home/me/%2essh/%69d_rsa"
            : params.plant === "object"
              ? { note: "file:///home/me/.ssh/id_rsa" }
              : params.plant === "token"
                ? "ghp_" + "a1B2c3D4".repeat(5)
                : "requestId" in params
                  ? params.requestId
                  : 9001;
    const plantResult = params.plantResult;
    const plantError = params.plantError;
    delete params.requestId;
    delete params.plant;
    delete params.plantResult;
    delete params.plantError;
    const request = { jsonrpc: "2.0", id, method: "sampling/createMessage", params };
    if (plantResult !== undefined) request.result = plantResult;
    if (plantError !== undefined) request.error = plantError;
    send(request);
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/progress") {
    send({ jsonrpc: "2.0", method: "notifications/progress", params: msg.params });
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/reply") {
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    if (params.plant === "token") {
      const token = "ghp_" + "a1B2c3D4".repeat(5);
      send({ jsonrpc: "2.0", id: msg.id, result: { message: `your token is ${token}` } });
    } else if ("error" in params && "result" in params) {
      send({ jsonrpc: "2.0", id: msg.id, result: params.result, error: params.error });
    } else if ("error" in params) {
      send({ jsonrpc: "2.0", id: msg.id, error: params.error });
    } else {
      send({ jsonrpc: "2.0", id: msg.id, result: "result" in params ? params.result : { ok: true } });
    }
  } else if (msg.method === "test/ask") {
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    send(
      copyBody(
        {
          jsonrpc: "2.0",
          id: 9004,
          method: "method" in params ? params.method : "custom/ask",
          params: "params" in params ? params.params : {},
        },
        params,
      ),
    );
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/notify") {
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    const note = { jsonrpc: "jsonrpc" in params ? params.jsonrpc : "2.0", method: params.method };
    if ("params" in params) note.params = params.params;
    copyBody(note, params);
    attachNote(note, params);
    send(note);
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/batch") {
    if (msg.params && "batch" in msg.params) send(msg.params.batch);
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/updated") {
    send({ jsonrpc: "2.0", method: "notifications/resources/updated", params: msg.params });
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/cancel") {
    send({ jsonrpc: "2.0", method: "notifications/cancelled", params: msg.params });
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/log") {
    send({ jsonrpc: "2.0", method: "notifications/message", params: msg.params });
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "test/elicitation") {
    send({ jsonrpc: "2.0", id: 9002, method: "elicitation/create", params: msg.params });
    send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (
    msg.method === "notifications/cancelled" ||
    msg.method === "logging/setLevel" ||
    msg.method === "custom/read"
  ) {
    if (callsFile) {
      const seen = { method: msg.method, params: msg.params };
      if (msg.note !== undefined) seen.note = msg.note;
      appendFileSync(callsFile, JSON.stringify(seen) + "\n");
    }
    if (msg.id !== undefined) send({ jsonrpc: "2.0", id: msg.id, result: { ok: true } });
  } else if (msg.method === "tools/list") {
    noteMarked(msg);
    if (msg.params && msg.params.error && typeof msg.params.error === "object") {
      send({ jsonrpc: "2.0", id: msg.id, error: msg.params.error });
      return;
    }
    const result = listResult(msg.params?.cursor);
    if (typeof msg.params?.nextCursor === "string") result.nextCursor = msg.params.nextCursor;
    if (msg.params && "extra" in msg.params) result.extra = msg.params.extra;
    sendResult(msg.id, result, msg.params);
  } else if (msg.method === "resources/list") {
    noteMarked(msg);
    if (msg.params && msg.params.error && typeof msg.params.error === "object") {
      send({ jsonrpc: "2.0", id: msg.id, error: msg.params.error });
      return;
    }
    const resources = Array.isArray(msg.params?.resources) ? msg.params.resources : [];
    const result = { resources };
    if (typeof msg.params?.nextCursor === "string") result.nextCursor = msg.params.nextCursor;
    sendResult(msg.id, result, msg.params);
  } else if (msg.method === "prompts/list") {
    const prompts = msg.params && "prompts" in msg.params ? msg.params.prompts : [];
    send({ jsonrpc: "2.0", id: msg.id, result: { prompts } });
  } else if (msg.method === "resources/templates/list") {
    const resourceTemplates = Array.isArray(msg.params?.resourceTemplates) ? msg.params.resourceTemplates : [];
    send({ jsonrpc: "2.0", id: msg.id, result: { resourceTemplates } });
  } else if (msg.method === "resources/subscribe" || msg.method === "resources/unsubscribe") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    if (params.plant === "token") {
      const token = "ghp_" + "a1B2c3D4".repeat(5);
      send({ jsonrpc: "2.0", id: msg.id, result: { message: `your token is ${token}` } });
    } else if ("error" in params && "result" in params) {
      send({ jsonrpc: "2.0", id: msg.id, result: params.result, error: params.error });
    } else if ("error" in params) {
      send({ jsonrpc: "2.0", id: msg.id, error: params.error });
    } else if ("result" in params) {
      send({ jsonrpc: "2.0", id: msg.id, result: params.result });
    } else {
      send({ jsonrpc: "2.0", id: msg.id, result: {} });
    }
  } else if (msg.method === "resources/read") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify(envelope({ method: msg.method, params: msg.params }, msg)) + "\n");
    const uri = typeof msg.params?.uri === "string" ? msg.params.uri : "file://doc";
    if (typeof msg.params?.blob === "string") {
      send({ jsonrpc: "2.0", id: msg.id, result: { contents: [{ uri, mimeType: "text/plain", blob: msg.params.blob }] } });
      return;
    }
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
  } else if (msg.method === "completion/complete") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
    if (typeof msg.params?.fail === "string") {
      const error = { code: -32000, message: msg.params.fail };
      if (msg.params.failData && typeof msg.params.failData === "object") error.data = msg.params.failData;
      send({ jsonrpc: "2.0", id: msg.id, error });
      return;
    }
    const value = typeof msg.params?.argument?.value === "string" ? msg.params.argument.value : "";
    const values = Array.isArray(msg.params?.suggestions)
      ? msg.params.suggestions
      : value === ""
        ? []
        : [value + "-done"];
    sendResult(msg.id, { completion: { values, hasMore: false } }, msg.params);
  } else if (msg.method === "tools/call") {
    if (callsFile) appendFileSync(callsFile, JSON.stringify(envelope(msg.params, msg)) + "\n");
    if (msg.params?.arguments && "rawResult" in msg.params.arguments) {
      const message = { jsonrpc: "2.0", id: msg.id, result: msg.params.arguments.rawResult };
      if (msg.params.arguments.beside && typeof msg.params.arguments.beside === "object") message.error = msg.params.arguments.beside;
      if ("looseMethod" in msg.params.arguments) message.method = msg.params.arguments.looseMethod;
      send(message);
      return;
    }
    if (msg.params?.arguments && "rawError" in msg.params.arguments) {
      send({ jsonrpc: "2.0", id: msg.id, error: msg.params.arguments.rawError });
      return;
    }
    if (typeof msg.params?.arguments?.fail === "string") {
      const error = { code: -32000, message: msg.params.arguments.fail };
      if (msg.params.arguments.failData && typeof msg.params.arguments.failData === "object") {
        error.data = msg.params.arguments.failData;
      }
      send(attachNote({ jsonrpc: "2.0", id: msg.id, error }, msg.params.arguments));
      return;
    }
    if (typeof msg.params?.arguments?.image === "string" || typeof msg.params?.arguments?.audio === "string") {
      const audio = typeof msg.params.arguments.audio === "string";
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [
            {
              type: audio ? "audio" : "image",
              mimeType: audio ? "audio/wav" : "image/png",
              data: audio ? msg.params.arguments.audio : msg.params.arguments.image,
            },
          ],
          isError: false,
        },
      });
      return;
    }
    if (typeof msg.params?.arguments?.blob === "string") {
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [{ type: "resource", resource: { uri: "file://out", mimeType: "text/plain", blob: msg.params.arguments.blob } }],
          isError: false,
        },
      });
      return;
    }
    const result = {
      content: [{ type: "text", text: msg.params.arguments?.echo ?? "ran " + msg.params.name }],
      isError: false,
    };
    if (msg.params?.arguments?.structured && typeof msg.params.arguments.structured === "object") {
      result.structuredContent = msg.params.arguments.structured;
    }
    send(attachNote({ jsonrpc: "2.0", id: msg.id, result }, msg.params?.arguments));
  } else if (msg.method === undefined && msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
    if (callsFile) appendFileSync(callsFile, JSON.stringify(msg) + "\n");
  } else if (msg.id !== undefined) {
    if (callsFile) appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
  } else if (typeof msg.method === "string" && callsFile) {
    appendFileSync(callsFile, JSON.stringify({ method: msg.method, params: msg.params }) + "\n");
  }
}
