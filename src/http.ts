import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Firewall } from "./firewall.js";

/**
 * A local HTTP proxy for remote MCP servers ("Streamable HTTP" transport).
 *
 *   AI app  →  http://127.0.0.1:<port>/  →  toolwarden  →  https://remote/mcp
 *
 * The client talks to the local port instead of the remote URL. Requests are
 * JSON-RPC in POST bodies; responses are either one JSON document or a stream
 * of server-sent events, and both are inspected.
 */

export interface HttpProxyOptions {
  target: string;
  port: number;
  host?: string;
}

/** Headers that describe one hop and must not be copied across. */
const HOP_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "content-length",
  "content-encoding",
  "accept-encoding",
  "upgrade",
  "te",
  "trailer",
  "proxy-authorization",
  "proxy-authenticate",
]);

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function forwardHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined || HOP_HEADERS.has(k.toLowerCase()) || k.toLowerCase() === "origin") continue;
    out[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  // Ask for an uncompressed body so it can be inspected.
  out["accept-encoding"] = "identity";
  return out;
}

function copyResponseHeaders(upstream: Response, res: ServerResponse): void {
  upstream.headers.forEach((value, key) => {
    if (!HOP_HEADERS.has(key.toLowerCase())) res.setHeader(key, value);
  });
}

/** Run one server message (or batch) through the firewall; return the text to send on. */
function inspectServerPayload(firewall: Firewall, raw: string, scope: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return raw;
  }
  if (Array.isArray(parsed)) {
    let changed = false;
    const out = parsed.map((item) => {
      const replacement = firewall.onServerMessage(item, scope);
      if (replacement !== null) changed = true;
      return replacement ?? item;
    });
    return changed ? JSON.stringify(out) : raw;
  }
  const replacement = firewall.onServerMessage(parsed, scope);
  return replacement === null ? raw : JSON.stringify(replacement);
}

/** Rewrite one server-sent event, inspecting its data payload. */
function inspectSseEvent(firewall: Firewall, block: string, scope: string): string {
  const lines = block.split(/\r?\n/);
  const data: string[] = [];
  const other: string[] = [];
  for (const line of lines) {
    if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    else other.push(line);
  }
  if (data.length === 0) return block;
  const original = data.join("\n");
  const inspected = inspectServerPayload(firewall, original, scope);
  if (inspected === original) return block;
  return [...other.filter((l) => l.length > 0), "data: " + inspected].join("\n");
}

async function pipeSse(firewall: Firewall, upstream: Response, res: ServerResponse, scope: string): Promise<void> {
  if (!upstream.body) {
    res.end();
    return;
  }
  const decoder = new TextDecoder();
  let buffer = "";
  for await (const chunk of upstream.body as unknown as AsyncIterable<Uint8Array>) {
    buffer += decoder.decode(chunk, { stream: true });
    // Events are separated by a blank line.
    for (;;) {
      const match = /\r?\n\r?\n/.exec(buffer);
      if (!match) break;
      const block = buffer.slice(0, match.index);
      buffer = buffer.slice(match.index + match[0].length);
      res.write(inspectSseEvent(firewall, block, scope) + "\n\n");
    }
  }
  if (buffer.trim().length > 0) res.write(inspectSseEvent(firewall, buffer, scope) + "\n\n");
  res.end();
}

function isLocalHost(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  const host = hostHeader.replace(/:\d+$/, "").toLowerCase();
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]";
}

function isLocalOrigin(origin: string | undefined): boolean {
  if (!origin) return true; // non-browser clients send no Origin
  try {
    return isLocalHost(new URL(origin).host);
  } catch {
    return false;
  }
}

export function startHttpProxy(firewall: Firewall, opts: HttpProxyOptions): Promise<Server> {
  const host = opts.host ?? "127.0.0.1";
  let counter = 0;

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    // A web page must not be able to reach this proxy: reject foreign Host and Origin
    // headers (DNS-rebinding and cross-site requests).
    if (!isLocalHost(req.headers.host) || !isLocalOrigin(req.headers.origin as string | undefined)) {
      res.writeHead(403, { "content-type": "text/plain" }).end("toolwarden: this proxy only accepts local requests\n");
      return;
    }

    const scope = "http" + ++counter;
    const method = req.method ?? "GET";
    const headers = forwardHeaders(req);
    const abort = new AbortController();
    res.on("close", () => abort.abort());

    let body: string | undefined;
    const extraReplies: unknown[] = [];

    if (method === "POST") {
      const raw = (await readBody(req)).toString("utf8");
      body = raw;
      let parsed: unknown;
      let parsedOk = true;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsedOk = false;
      }

      if (parsedOk && Array.isArray(parsed)) {
        const forwarded: unknown[] = [];
        let replaced = false;
        for (const item of parsed) {
          const d = firewall.onClientMessage(item, scope);
          if (d.send) {
            forwarded.push(d.send);
            replaced = true;
          } else if (d.forward) forwarded.push(item);
          if (d.reply) extraReplies.push(d.reply);
        }
        if (forwarded.length === 0) {
          if (extraReplies.length > 0) {
            res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(extraReplies));
          } else {
            res.writeHead(202).end();
          }
          return;
        }
        if (replaced || forwarded.length !== parsed.length) body = JSON.stringify(forwarded);
      } else if (parsedOk) {
        const d = firewall.onClientMessage(parsed, scope);
        if (d.send) body = JSON.stringify(d.send);
        else if (!d.forward) {
          if (d.reply) res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(d.reply));
          else res.writeHead(202).end();
          return;
        }
      }
    }

    let upstream: Response;
    try {
      upstream = await fetch(opts.target, {
        method,
        headers,
        body: method === "GET" || method === "HEAD" ? undefined : body,
        signal: abort.signal,
        redirect: "manual",
      });
    } catch (err) {
      if (abort.signal.aborted) return;
      res
        .writeHead(502, { "content-type": "text/plain" })
        .end(`toolwarden: could not reach ${opts.target}: ${(err as Error).message}\n`);
      return;
    }

    const contentType = (upstream.headers.get("content-type") ?? "").toLowerCase();
    copyResponseHeaders(upstream, res);

    try {
      if (contentType.includes("text/event-stream")) {
        res.writeHead(upstream.status);
        for (const reply of extraReplies) res.write("data: " + JSON.stringify(reply) + "\n\n");
        await pipeSse(firewall, upstream, res, scope);
        return;
      }

      if (contentType.includes("application/json")) {
        const text = await upstream.text();
        let out = inspectServerPayload(firewall, text, scope);
        if (extraReplies.length > 0) {
          try {
            const parsed: unknown = JSON.parse(out);
            out = JSON.stringify([...(Array.isArray(parsed) ? parsed : [parsed]), ...extraReplies]);
          } catch {
            /* leave the upstream body as it is */
          }
        }
        res.writeHead(upstream.status).end(out);
        return;
      }

      // Anything else (empty 202s, errors, auth pages) passes through unchanged.
      res.writeHead(upstream.status);
      if (upstream.body) {
        for await (const chunk of upstream.body as unknown as AsyncIterable<Uint8Array>) res.write(chunk);
      }
      res.end();
    } catch {
      // The client or the upstream went away mid-stream.
      res.end();
    }
  };

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      handle(req, res).catch((err: Error) => {
        if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain" });
        res.end(`toolwarden: internal error: ${err.message}\n`);
      });
    });
    server.on("error", reject);
    server.listen(opts.port, host, () => resolve(server));
  });
}
