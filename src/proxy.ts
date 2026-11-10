import { spawn } from "node:child_process";
import type { Firewall } from "./firewall.js";

/** Splits a byte stream into newline-delimited lines (MCP's stdio framing). */
class LineSplitter {
  private buffer = "";

  constructor(private readonly onLine: (line: string) => void) {}

  push(chunk: Buffer | string): void {
    this.buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, "");
      this.buffer = this.buffer.slice(idx + 1);
      if (line.length > 0) this.onLine(line);
    }
  }

  flush(): void {
    const rest = this.buffer.trim();
    this.buffer = "";
    if (rest.length > 0) this.onLine(rest);
  }
}

/** Quote one argument for cmd.exe so spaces and shell characters stay literal. */
export function quoteForWindowsShell(arg: string): string {
  if (arg.length > 0 && !/[\s"&|<>^()%!,;=]/.test(arg)) return arg;
  // Double any backslashes that come before a quote or the end, then escape the quotes.
  const escaped = arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1");
  return `"${escaped}"`;
}

function tryParse(line: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(line) };
  } catch {
    return { ok: false };
  }
}

/**
 * Run the wrapped MCP server as a child process and sit between it and the
 * client. Resolves with the exit code the proxy should exit with.
 */
export function runProxy(firewall: Firewall, command: string, args: string[]): Promise<number> {
  return new Promise((resolve) => {
    // On Windows, commands such as npx are .cmd scripts, which can only be started
    // through the shell. Arguments are quoted so the shell passes them on unchanged.
    const child =
      process.platform === "win32"
        ? spawn([command, ...args].map(quoteForWindowsShell).join(" "), { stdio: ["pipe", "pipe", "inherit"], shell: true })
        : spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
    let settled = false;
    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      resolve(code);
    };

    child.on("error", (err) => {
      process.stderr.write(`[toolwarden] could not start "${command}": ${err.message}\n`);
      finish(127);
    });

    const toClient = (line: string) => {
      if (process.stdout.writable) process.stdout.write(line + "\n");
    };
    // If the client goes away, stop the server too instead of crashing on a broken pipe.
    process.stdout.on("error", () => {
      child.kill("SIGTERM");
      finish(0);
    });
    const toServer = (line: string) => {
      if (child.stdin.writable) child.stdin.write(line + "\n");
    };

    // Client → server
    const fromClient = new LineSplitter((line) => {
      const parsed = tryParse(line);
      if (!parsed.ok) return toServer(line);

      // JSON-RPC batches are rare in MCP, but handle them element by element.
      if (Array.isArray(parsed.value)) {
        const forwarded: unknown[] = [];
        for (const item of parsed.value) {
          const d = firewall.onClientMessage(item);
          if (d.forward) forwarded.push(item);
          if (d.reply) toClient(JSON.stringify(d.reply));
        }
        if (forwarded.length === parsed.value.length) toServer(line);
        else if (forwarded.length > 0) toServer(JSON.stringify(forwarded));
        return;
      }

      const decision = firewall.onClientMessage(parsed.value);
      if (decision.forward) toServer(line);
      if (decision.reply) toClient(JSON.stringify(decision.reply));
    });

    // Server → client
    const fromServer = new LineSplitter((line) => {
      const parsed = tryParse(line);
      if (!parsed.ok) return toClient(line);

      if (Array.isArray(parsed.value)) {
        let changed = false;
        const out = parsed.value.map((item) => {
          const replacement = firewall.onServerMessage(item);
          if (replacement !== null) changed = true;
          return replacement ?? item;
        });
        return toClient(changed ? JSON.stringify(out) : line);
      }

      const replacement = firewall.onServerMessage(parsed.value);
      toClient(replacement === null ? line : JSON.stringify(replacement));
    });

    process.stdin.on("data", (chunk) => fromClient.push(chunk));
    process.stdin.on("end", () => {
      fromClient.flush();
      child.stdin.end();
    });
    child.stdin.on("error", () => {
      /* the server closed its input; its exit handler will finish the run */
    });

    child.stdout.on("data", (chunk) => fromServer.push(chunk));
    child.stdout.on("end", () => fromServer.flush());

    child.on("exit", (code, signal) => {
      // Let any buffered output drain before reporting the exit.
      setImmediate(() => finish(code ?? (signal ? 1 : 0)));
    });

    for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
      process.on(sig, () => child.kill(sig));
    }
  });
}
