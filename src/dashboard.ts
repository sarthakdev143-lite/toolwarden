import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { join } from "node:path";
import { DASHBOARD_HTML } from "./dashboard-page.js";
import { approve, listServers, loadPins, savePins } from "./pins.js";
import { scanTool } from "./scan.js";

/**
 * A local web page for reviewing changes and watching the audit log.
 *
 * It can approve tool changes, so it is locked down: it listens on 127.0.0.1
 * only, every API call needs a random token that is printed in the terminal,
 * and requests with a foreign Host or Origin header are refused. Without this,
 * any web page you visit could ask your browser to approve a malicious change.
 */

type Json = Record<string, unknown>;

function describe(def: unknown): { description: string; schema: string } {
  const d = (def ?? {}) as Json;
  return {
    description: typeof d.description === "string" ? d.description : "",
    schema: JSON.stringify(d.inputSchema ?? null, null, 2),
  };
}

function readLog(stateDir: string, limit: number): Json[] {
  const path = join(stateDir, "audit.log");
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean).slice(-limit);
  const out: Json[] = [];
  for (const line of lines) {
    try {
      out.push(JSON.parse(line) as Json);
    } catch {
      /* skip a damaged line */
    }
  }
  return out;
}

function buildState(stateDir: string): Json {
  const servers = listServers(stateDir).flatMap((name) => {
    const pins = loadPins(stateDir, name);
    if (!pins) return [];
    return [
      {
        server: pins.server,
        command: pins.command,
        createdAt: pins.createdAt,
        tools: Object.entries(pins.tools)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([tool, entry]) => ({ name: tool, description: describe(entry.definition).description, pinnedAt: entry.pinnedAt })),
        pending: Object.entries(pins.pending)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([tool, entry]) => ({
            name: tool,
            kind: entry.kind,
            seenAt: entry.seenAt,
            before: entry.kind === "changed" ? describe(pins.tools[tool]?.definition) : null,
            after: describe(entry.definition),
            warnings: scanTool(entry.definition).map((f) => f.message),
          })),
      },
    ];
  });

  const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const recent = readLog(stateDir, 20000).filter((r) => Date.parse(String(r.ts)) >= dayAgo);
  const count = (events: string[]) => recent.filter((r) => events.includes(String(r.event))).length;
  return {
    servers,
    stats: {
      calls: count(["call"]),
      blocked: count(["call_blocked", "call_denied", "result_blocked", "flow_denied"]),
      warnings: count(["call_warning", "result_warning", "definition_warning"]) + recent.filter((r) => r.event === "flow" && r.warned === true).length,
    },
  };
}

function isLocalHost(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  const host = hostHeader.replace(/:\d+$/, "").toLowerCase();
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]";
}

function isLocalOrigin(origin: string | undefined): boolean {
  if (!origin) return true;
  try {
    return isLocalHost(new URL(origin).host);
  } catch {
    return false;
  }
}

function tokenMatches(given: string | undefined, expected: string): boolean {
  if (typeof given !== "string") return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 100_000) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
}

export interface Dashboard {
  server: Server;
  url: string;
  token: string;
}

export function startDashboard(stateDir: string, port: number, token = randomBytes(24).toString("base64url")): Promise<Dashboard> {
  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (!isLocalHost(req.headers.host) || !isLocalOrigin(req.headers.origin as string | undefined)) {
      res.writeHead(403, { "content-type": "text/plain" }).end("toolwarden: local requests only\n");
      return;
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (req.method === "GET" && url.pathname === "/") {
      const nonce = randomBytes(16).toString("base64");
      res
        .writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "referrer-policy": "no-referrer",
          "x-frame-options": "DENY",
          "content-security-policy": `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'`,
        })
        .end(DASHBOARD_HTML.replaceAll("__NONCE__", nonce));
      return;
    }

    if (!url.pathname.startsWith("/api/")) {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found\n");
      return;
    }
    if (!tokenMatches(req.headers["x-toolwarden-token"] as string | undefined, token)) {
      sendJson(res, 401, { error: "missing or wrong token. Open the link printed by 'toolwarden dashboard'." });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/state") {
      sendJson(res, 200, buildState(stateDir));
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/log") {
      const limit = Math.min(1000, Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "300", 10) || 300));
      sendJson(res, 200, { records: readLog(stateDir, limit).reverse() });
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/approve") {
      if (!(req.headers["content-type"] ?? "").includes("application/json")) {
        sendJson(res, 415, { error: "send JSON" });
        return;
      }
      let body: unknown;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        sendJson(res, 400, { error: (err as Error).message });
        return;
      }
      const b = (body ?? {}) as Json;
      const tools = Array.isArray(b.tools) ? b.tools.filter((t): t is string => typeof t === "string") : [];
      if (typeof b.server !== "string" || tools.length === 0) {
        sendJson(res, 400, { error: "need a server and at least one tool" });
        return;
      }
      const pins = listServers(stateDir).includes(b.server) ? loadPins(stateDir, b.server) : null;
      if (!pins) {
        sendJson(res, 404, { error: "no such server" });
        return;
      }
      const approved = approve(pins, tools);
      if (approved.length > 0) savePins(stateDir, pins);
      sendJson(res, 200, { approved });
      return;
    }
    sendJson(res, 404, { error: "not found" });
  };

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      handle(req, res).catch((err: Error) => {
        if (!res.headersSent) sendJson(res, 500, { error: err.message });
        else res.end();
      });
    });
    server.on("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : port;
      resolve({ server, token, url: `http://127.0.0.1:${actualPort}/#${token}` });
    });
  });
}
