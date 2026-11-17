import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AccountError, AccountStore, type PublicAccount } from "./accounts.js";
import { adminPage, signInPage } from "./admin-page.js";
import { KNOWN_LIMITS, readDecisions } from "./operator-view.js";

/**
 * The long-lived operator service. `npm start` and `toolwarden serve` both
 * call this and keep listening. It signs in the person operating toolwarden.
 * It does not complete OAuth for an MCP server, and it does not proxy MCP
 * traffic. That stays on `toolwarden run` and `toolwarden http`.
 */

export interface HostedOptions {
  host: string;
  port: number;
  dataDir: string;
  publicUrl?: string;
  signup?: string;
}

export interface Hosted {
  server: Server;
  url: string;
  publicUrl?: string;
}

const SECURITY_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  // same-origin, not no-referrer: Chrome sends Origin: null for a form when the
  // policy is no-referrer, and the cross-site check would then refuse the operator.
  "referrer-policy": "same-origin",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
};

function signupMode(value: string | undefined): "open" | "closed" {
  if (value === undefined || value === "" || value === "open") return "open";
  if (value === "closed") return "closed";
  throw new Error('TOOLWARDEN_SIGNUP must be "open" or "closed"');
}

function checkedPublicUrl(value: string | undefined): string | undefined {
  if (value === undefined || value === "") return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("TOOLWARDEN_PUBLIC_URL is not a valid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("TOOLWARDEN_PUBLIC_URL must start with http:// or https://");
  }
  return value;
}

function hostForUrl(host: string): string {
  if (host === "0.0.0.0" || host === "::") return "127.0.0.1";
  return host.includes(":") ? `[${host}]` : host;
}

function nonce(): string {
  return randomBytes(16).toString("base64");
}

function contentSecurityPolicy(value: string): string {
  return `default-src 'none'; style-src 'nonce-${value}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 100_000) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function cookieValue(header: string | string[] | undefined, name: string): string | undefined {
  const raw = Array.isArray(header) ? header.join(";") : header;
  if (!raw) return undefined;
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function sessionCookie(id: string, maxAge: number, secure: boolean): string {
  const parts = [`toolwarden_session=${encodeURIComponent(id)}`, "HttpOnly", "SameSite=Lax", "Path=/", `Max-Age=${maxAge}`];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function clearCookie(secure: boolean): string {
  const parts = ["toolwarden_session=", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=0"];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

/** A browser form posted from another site must not change an operator session. */
function sameSitePost(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  const host = req.headers.host;
  if (!host || Array.isArray(origin)) return false;
  try {
    return new URL(origin).host.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}

function html(res: ServerResponse, status: number, htmlText: string, headerNonce: string, cookie?: string): void {
  const headers: Record<string, string | string[]> = {
    ...SECURITY_HEADERS,
    "content-security-policy": contentSecurityPolicy(headerNonce),
  };
  if (cookie) headers["set-cookie"] = cookie;
  res.writeHead(status, headers).end(htmlText);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }).end(JSON.stringify(body));
}

function redirect(res: ServerResponse, location: string, cookie?: string): void {
  const headers: Record<string, string | string[]> = { location, "cache-control": "no-store" };
  if (cookie) headers["set-cookie"] = cookie;
  res.writeHead(303, headers).end();
}

export function startHosted(opts: HostedOptions): Promise<Hosted> {
  const signup = signupMode(opts.signup);
  const publicUrl = checkedPublicUrl(opts.publicUrl);
  const secure = publicUrl?.startsWith("https://") ?? false;
  const store = new AccountStore(opts.dataDir);

  const currentAccount = (req: IncomingMessage): PublicAccount | null => {
    const id = cookieValue(req.headers.cookie, "toolwarden_session");
    if (!id) return null;
    return store.accountForSession(id);
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const method = req.method ?? "GET";

    if (method === "POST" && !sameSitePost(req)) {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8" }).end("cross-site request refused\n");
      return;
    }

    if (method === "GET" && url.pathname === "/") {
      const value = nonce();
      html(res, 200, signInPage(value), value);
      return;
    }
    if (method === "GET" && (url.pathname === "/login" || url.pathname === "/signup")) {
      redirect(res, "/");
      return;
    }
    if (method === "GET" && url.pathname === "/logout") {
      res.writeHead(405, { allow: "POST", "content-type": "text/plain; charset=utf-8" }).end("method not allowed\n");
      return;
    }

    if (method === "GET" && url.pathname === "/admin") {
      let account: PublicAccount | null;
      try {
        account = currentAccount(req);
      } catch (err) {
        res.writeHead(500, { "content-type": "text/plain; charset=utf-8" }).end((err as Error).message + "\n");
        return;
      }
      if (!account) {
        redirect(res, "/");
        return;
      }
      const value = nonce();
      html(res, 200, adminPage(value, account, readDecisions(account.stateDir)), value);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin") {
      let account: PublicAccount | null;
      try {
        account = currentAccount(req);
      } catch (err) {
        sendJson(res, 500, { error: (err as Error).message });
        return;
      }
      if (!account) {
        sendJson(res, 401, { error: "Sign in again." });
        return;
      }
      sendJson(res, 200, {
        account,
        decisions: readDecisions(account.stateDir),
        limits: [...KNOWN_LIMITS],
      });
      return;
    }

    if (method === "POST" && (url.pathname === "/login" || url.pathname === "/signup" || url.pathname === "/logout")) {
      if (url.pathname === "/logout") {
        const id = cookieValue(req.headers.cookie, "toolwarden_session");
        if (id) store.destroySession(id);
        redirect(res, "/", clearCookie(secure));
        return;
      }

      const type = req.headers["content-type"] ?? "";
      if (!type.includes("application/x-www-form-urlencoded")) {
        res.writeHead(415, { "content-type": "text/plain; charset=utf-8" }).end("send a form\n");
        return;
      }
      const fields = new URLSearchParams(await readBody(req));
      const email = fields.get("email") ?? "";
      const password = fields.get("password") ?? "";

      if (url.pathname === "/signup") {
        if (signup === "closed") {
          const value = nonce();
          html(res, 403, signInPage(value, "signup is closed"), value);
          return;
        }
        try {
          const account = store.signup(email, password);
          const session = store.createSession(account.id);
          redirect(res, "/admin", sessionCookie(session.id, session.maxAgeSeconds, secure));
        } catch (err) {
          if (err instanceof AccountError) {
            const value = nonce();
            html(res, err.status, signInPage(value, err.message), value);
            return;
          }
          throw err;
        }
        return;
      }

      const account = store.authenticate(email, password);
      if (!account) {
        const value = nonce();
        html(res, 401, signInPage(value, "The email or password is wrong."), value);
        return;
      }
      const session = store.createSession(account.id);
      // A posted `next` is ignored. The only signed-in page is this server's admin.
      redirect(res, "/admin", sessionCookie(session.id, session.maxAgeSeconds, secure));
      return;
    }

    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }).end("not found\n");
  };

  return new Promise((resolveListen, reject) => {
    const server = createServer((req, res) => {
      handle(req, res).catch((err: Error) => {
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "text/plain; charset=utf-8" }).end("toolwarden: internal error\n");
        } else {
          res.end();
        }
        process.stderr.write(`[toolwarden] ${err.message}\n`);
      });
    });
    server.on("error", reject);
    server.listen(opts.port, opts.host, () => {
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : opts.port;
      resolveListen({
        server,
        url: `http://${hostForUrl(opts.host)}:${actualPort}/`,
        publicUrl,
      });
    });
  });
}
