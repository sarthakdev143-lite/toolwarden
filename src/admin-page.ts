import { KNOWN_LIMITS, type OperatorDecision } from "./operator-view.js";
import { escapeHtml } from "./html.js";

/**
 * The operator pages. Server-rendered on purpose: account names and audit text
 * are written as text, and the page works without a script. This is the sign-in
 * for the person running toolwarden, not a product brochure.
 */

function page(title: string, nonce: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style nonce="${escapeHtml(nonce)}">
:root { --bg: #f6f5f1; --surface: #fff; --line: #e2dfd6; --text: #1d1c19; --muted: #6b675e; --bad: #b3261e; --bad-bg: #fbe9e7; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #131412; --surface: #1c1d1a; --line: #2e302b; --text: #ecebe6; --muted: #9a978d; --bad: #ff8a80; --bad-bg: #3a1a17; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, sans-serif; }
main { max-width: 720px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 8px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin: 28px 0 8px; }
p, li { margin: 0 0 10px; }
form { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px; margin: 0 0 16px; }
label { display: block; margin: 0 0 10px; }
input { display: block; width: 100%; margin-top: 4px; font: inherit; padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--text); }
button { font: inherit; font-weight: 600; padding: 8px 14px; border-radius: 8px; border: 1px solid var(--text); background: var(--text); color: var(--bg); cursor: pointer; }
.error { background: var(--bad-bg); color: var(--bad); padding: 12px 14px; border-radius: 10px; margin: 0 0 16px; }
.meta { color: var(--muted); }
dl { margin: 0; background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 12px 16px; }
dt { color: var(--muted); font-size: 13px; }
dd { margin: 0 0 10px; overflow-wrap: anywhere; }
ul { padding-left: 18px; }
li { overflow-wrap: anywhere; }
</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>
`;
}

function limitsList(): string {
  return `<ul>${KNOWN_LIMITS.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`;
}

export function signInPage(nonce: string, error?: string): string {
  const notice = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  return page(
    "toolwarden",
    nonce,
    `<h1>toolwarden</h1>
<p>Sign in with an email and a password for this server. This is the operator session. It is not the OAuth sign-in a remote MCP server may ask your AI app for.</p>
${notice}
<h2>Sign in</h2>
<form method="post" action="/login">
<label>Email <input name="email" type="email" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
<h2>Create an account</h2>
<form method="post" action="/signup">
<label>Email <input name="email" type="email" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="new-password" required minlength="8"></label>
<button type="submit">Create account</button>
</form>
<h2>Known limits</h2>
${limitsList()}
<p class="meta">This build does not verify email, reset a lost password, or use an SSO vendor. There is no payment provider. Anyone who can open this URL can create an account until the process is started with TOOLWARDEN_SIGNUP=closed.</p>`,
  );
}

export function adminPage(
  nonce: string,
  account: { id: string; email: string; createdAt: string; stateDir: string },
  decisions: OperatorDecision[],
  mcp: { clientUrl: string; sessionId: string } | null,
): string {
  const rows =
    decisions.length === 0
      ? `<p class="meta">No decisions recorded for this account yet.</p>`
      : `<ul>${decisions
          .map((decision) => {
            const where = decision.tool ? `${decision.server} / ${decision.tool}` : decision.server;
            return `<li><span class="meta">${escapeHtml(decision.ts)}</span> ${escapeHtml(decision.event)} ${escapeHtml(where)} — ${escapeHtml(decision.summary)}</li>`;
          })
          .join("")}</ul>`;
  return page(
    "toolwarden",
    nonce,
    `<h1>toolwarden</h1>
<p>Signed in as ${escapeHtml(account.email)}.</p>
<h2>Account</h2>
<dl>
<dt>Email</dt><dd>${escapeHtml(account.email)}</dd>
<dt>Account</dt><dd>${escapeHtml(account.id)}</dd>
<dt>Created</dt><dd>${escapeHtml(account.createdAt)}</dd>
<dt>State directory</dt><dd>${escapeHtml(account.stateDir)}</dd>
</dl>
<h2>MCP proxy</h2>
${
  mcp === null
    ? `<p class="meta">no MCP server is configured for this process. Set TOOLWARDEN_MCP_URL, then restart, to put this account in front of one.</p>`
    : `<p>Point the AI app at this URL. Send <code>x-toolwarden-session</code> with the session below. This browser's cookie is that same session. The MCP server's Authorization header is its own sign-in, not this account.</p>
<dl>
<dt>MCP URL</dt><dd>${escapeHtml(mcp.clientUrl)}</dd>
<dt>Header</dt><dd>x-toolwarden-session: ${escapeHtml(mcp.sessionId)}</dd>
</dl>
<p class="meta">Pins and the audit log for that server stay in this account's state directory. Another account does not share them.</p>`
}
<h2>Recent decisions</h2>
${rows}
<h2>Known limits</h2>
${limitsList()}
<p class="meta">Hosting this service does not change the scanner. The checks do not stop every attack. There is no payment provider and no SSO vendor.</p>
<form method="post" action="/logout"><button type="submit">Sign out</button></form>`,
  );
}
