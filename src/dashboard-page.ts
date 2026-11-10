/**
 * The dashboard page. One self-contained document: no external requests.
 *
 * Everything shown here can contain attacker-controlled text (tool names and
 * descriptions come from MCP servers), so the script only ever writes it with
 * textContent, never as HTML.
 */
export const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>toolwarden</title>
<style nonce="__NONCE__">
:root {
  --bg: #f6f5f1; --surface: #ffffff; --line: #e2dfd6; --text: #1d1c19; --muted: #6b675e;
  --ok: #1f7a4d; --ok-bg: #e3f3ea; --bad: #b3261e; --bad-bg: #fbe9e7; --warn: #8a5a00; --warn-bg: #fdf1d6;
  --add-bg: #e3f3ea; --del-bg: #fbe9e7; --accent: #1d1c19; --accent-text: #ffffff;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131412; --surface: #1c1d1a; --line: #2e302b; --text: #ecebe6; --muted: #9a978d;
    --ok: #6fcf97; --ok-bg: #16301f; --bad: #ff8a80; --bad-bg: #3a1a17; --warn: #f2c166; --warn-bg: #362a0e;
    --add-bg: #16301f; --del-bg: #3a1a17; --accent: #ecebe6; --accent-text: #131412;
  }
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
.wrap { max-width: 1040px; margin: 0 auto; padding: 28px 16px 64px; }
header { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 650; font-size: 18px; letter-spacing: -0.01em; }
.brand svg { width: 22px; height: 22px; }
.pill { margin-left: auto; padding: 5px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; }
.pill.ok { background: var(--ok-bg); color: var(--ok); }
.pill.bad { background: var(--bad-bg); color: var(--bad); }
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 32px; }
.stat { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.stat b { display: block; font-size: 26px; font-weight: 650; font-variant-numeric: tabular-nums; line-height: 1.2; }
.stat span { color: var(--muted); font-size: 13px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin: 0 0 10px; font-weight: 650; }
section { margin-bottom: 32px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px; margin-bottom: 12px; }
.card.pending { border-left: 4px solid var(--bad); }
.card-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.tool { font-family: var(--mono); font-weight: 600; font-size: 15px; overflow-wrap: anywhere; }
.meta { color: var(--muted); font-size: 13px; }
.badge { font-size: 12px; font-weight: 600; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }
.badge.bad { background: var(--bad-bg); color: var(--bad); }
.badge.warn { background: var(--warn-bg); color: var(--warn); }
.badge.ok { background: var(--ok-bg); color: var(--ok); }
.badge.plain { background: var(--line); color: var(--muted); }
.diff { font-family: var(--mono); font-size: 13px; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; margin: 8px 0; }
.diff-label { padding: 6px 10px; color: var(--muted); border-bottom: 1px solid var(--line); font-family: system-ui, sans-serif; font-size: 12px; }
.diff div.line { padding: 3px 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
.diff .same { color: var(--muted); }
.diff .del { background: var(--del-bg); }
.diff .add { background: var(--add-bg); }
.warnings { margin: 10px 0 0; padding: 0; list-style: none; }
.warnings li { color: var(--warn); font-size: 14px; padding-left: 18px; position: relative; }
.warnings li::before { content: "!"; position: absolute; left: 4px; font-weight: 700; }
.actions { display: flex; gap: 10px; align-items: center; margin-top: 14px; flex-wrap: wrap; }
button { font: inherit; cursor: pointer; border-radius: 8px; padding: 7px 14px; border: 1px solid var(--line); background: var(--surface); color: var(--text); }
button.primary { background: var(--accent); color: var(--accent-text); border-color: var(--accent); font-weight: 600; }
button:focus-visible, summary:focus-visible { outline: 2px solid var(--ok); outline-offset: 2px; }
button[disabled] { opacity: 0.5; cursor: default; }
.empty { color: var(--muted); background: var(--surface); border: 1px dashed var(--line); border-radius: 10px; padding: 18px; }
details.server { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; margin-bottom: 8px; }
details.server summary { padding: 12px 16px; cursor: pointer; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; list-style: none; }
details.server summary::-webkit-details-marker { display: none; }
details.server .name { font-weight: 600; }
details.server .body { padding: 0 16px 14px; }
.cmd { font-family: var(--mono); font-size: 12px; color: var(--muted); overflow-wrap: anywhere; margin-bottom: 10px; }
.toolrow { display: grid; grid-template-columns: minmax(120px, 220px) 1fr; gap: 12px; padding: 6px 0; border-top: 1px solid var(--line); font-size: 14px; }
.toolrow .tool { font-size: 13px; }
.filters { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
.filters button { padding: 4px 12px; border-radius: 999px; font-size: 13px; }
.filters button[aria-pressed="true"] { background: var(--accent); color: var(--accent-text); border-color: var(--accent); }
.log { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.row { display: grid; grid-template-columns: 84px 132px minmax(0, 1fr); gap: 12px; padding: 9px 14px; border-top: 1px solid var(--line); font-size: 14px; align-items: baseline; }
.row:first-child { border-top: 0; }
.row time { color: var(--muted); font-variant-numeric: tabular-nums; font-size: 13px; }
.row .what { overflow-wrap: anywhere; }
.row .what .where { font-family: var(--mono); font-size: 13px; font-weight: 600; }
.row .what .detail { color: var(--muted); }
.error { background: var(--bad-bg); color: var(--bad); padding: 12px 16px; border-radius: 10px; margin-bottom: 20px; }
[hidden] { display: none !important; }
@media (max-width: 640px) {
  .stats { grid-template-columns: repeat(2, 1fr); }
  .row { grid-template-columns: 1fr; gap: 2px; }
  .toolrow { grid-template-columns: 1fr; gap: 2px; }
}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>
      toolwarden
    </div>
    <div id="pill" class="pill ok">Loading</div>
  </header>

  <div id="error" class="error" hidden></div>

  <div class="stats">
    <div class="stat"><b id="s-servers">0</b><span>servers protected</span></div>
    <div class="stat"><b id="s-tools">0</b><span>approved tools</span></div>
    <div class="stat"><b id="s-blocked">0</b><span>blocked in 24 hours</span></div>
    <div class="stat"><b id="s-calls">0</b><span>calls in 24 hours</span></div>
  </div>

  <section>
    <h2>Waiting for your review</h2>
    <div id="pending"></div>
  </section>

  <section>
    <h2>Servers</h2>
    <div id="servers"></div>
  </section>

  <section>
    <h2>Activity</h2>
    <div class="filters" id="filters">
      <button type="button" data-filter="all" aria-pressed="true">All</button>
      <button type="button" data-filter="blocked" aria-pressed="false">Blocked</button>
      <button type="button" data-filter="warnings" aria-pressed="false">Warnings</button>
      <button type="button" data-filter="calls" aria-pressed="false">Calls</button>
    </div>
    <div id="log" class="log"></div>
  </section>
</div>

<script nonce="__NONCE__">
(function () {
  "use strict";

  // The token arrives in the URL fragment, which is never sent to a server.
  var token = location.hash.slice(1);
  try {
    if (token) { sessionStorage.setItem("tw-token", token); history.replaceState(null, "", location.pathname); }
    else { token = sessionStorage.getItem("tw-token") || ""; }
  } catch (e) { /* storage unavailable: the token stays in memory for this page */ }

  var filter = "all";
  var openServers = {};
  var lastPendingKey = null;
  var lastServersKey = null;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function $(id) { return document.getElementById(id); }

  function api(path, options) {
    options = options || {};
    options.headers = Object.assign({ "x-toolwarden-token": token }, options.headers || {});
    return fetch(path, options).then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok) throw new Error(body.error || ("request failed: " + res.status));
        return body;
      });
    });
  }

  function showError(message) {
    var box = $("error");
    box.textContent = message;
    box.hidden = !message;
  }

  function diffBlock(label, before, after) {
    var box = el("div", "diff");
    box.appendChild(el("div", "diff-label", label));
    if (before !== null) box.appendChild(el("div", "line del", "- " + (before || "(none)")));
    box.appendChild(el("div", "line add", "+ " + (after || "(none)")));
    return box;
  }

  // A line-by-line comparison (longest common subsequence), so only what changed is highlighted.
  function lineDiffBlock(label, before, after) {
    var a = before.split("\\n"), b = after.split("\\n");
    if (a.length * b.length > 250000) return diffBlock(label, before, after);
    var table = [], i, j;
    for (i = 0; i <= a.length; i++) { table.push(new Array(b.length + 1).fill(0)); }
    for (i = a.length - 1; i >= 0; i--) {
      for (j = b.length - 1; j >= 0; j--) {
        table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
      }
    }
    var box = el("div", "diff");
    box.appendChild(el("div", "diff-label", label));
    i = 0; j = 0;
    while (i < a.length || j < b.length) {
      if (i < a.length && j < b.length && a[i] === b[j]) { box.appendChild(el("div", "line same", "  " + a[i])); i++; j++; }
      else if (j < b.length && (i === a.length || table[i][j + 1] >= table[i + 1][j])) { box.appendChild(el("div", "line add", "+ " + b[j])); j++; }
      else { box.appendChild(el("div", "line del", "- " + a[i])); i++; }
    }
    return box;
  }

  function renderPending(servers) {
    var key = JSON.stringify(servers.map(function (s) { return [s.server, s.pending]; }));
    if (key === lastPendingKey) return;
    lastPendingKey = key;
    var root = $("pending");
    root.textContent = "";
    var total = 0;
    servers.forEach(function (s) {
      s.pending.forEach(function (p) {
        total++;
        var card = el("div", "card pending");
        var head = el("div", "card-head");
        head.appendChild(el("span", "tool", p.name));
        head.appendChild(el("span", "badge bad", p.kind === "changed" ? "Changed after approval" : "New tool"));
        head.appendChild(el("span", "meta", "on " + s.server + " · first seen " + new Date(p.seenAt).toLocaleString()));
        card.appendChild(head);

        var before = p.before;
        if (!before || before.description !== p.after.description) {
          card.appendChild(diffBlock("Description", before ? before.description : null, p.after.description));
        }
        if (before && before.schema !== p.after.schema) {
          card.appendChild(lineDiffBlock("Inputs", before.schema, p.after.schema));
        }
        if (before && before.description === p.after.description && before.schema === p.after.schema) {
          card.appendChild(el("div", "meta", "Another part of the definition changed (title, annotations or output format)."));
        }
        if (p.warnings.length > 0) {
          var list = el("ul", "warnings");
          p.warnings.forEach(function (w) { list.appendChild(el("li", null, "The new definition " + w + ".")); });
          card.appendChild(list);
        }

        var actions = el("div", "actions");
        var button = el("button", "primary", "Approve this change");
        button.type = "button";
        button.addEventListener("click", function () {
          button.disabled = true;
          api("/api/approve", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ server: s.server, tools: [p.name] })
          }).then(refresh).catch(function (err) { button.disabled = false; showError(err.message); });
        });
        actions.appendChild(button);
        actions.appendChild(el("span", "meta", "Until you approve it, this tool stays hidden from the AI and blocked."));
        card.appendChild(actions);
        root.appendChild(card);
      });
    });
    if (total === 0) root.appendChild(el("div", "empty", "Nothing is waiting. Every tool matches what you approved."));
    var pill = $("pill");
    pill.className = "pill " + (total === 0 ? "ok" : "bad");
    pill.textContent = total === 0 ? "All clear" : (total === 1 ? "1 change waiting" : total + " changes waiting");
    document.title = (total > 0 ? "(" + total + ") " : "") + "toolwarden";
  }

  function renderServers(servers) {
    var key = JSON.stringify(servers.map(function (s) { return [s.server, s.command, s.tools]; }));
    if (key === lastServersKey) return;
    lastServersKey = key;
    var root = $("servers");
    root.textContent = "";
    if (servers.length === 0) {
      root.appendChild(el("div", "empty", "No servers yet. Run \\"toolwarden init\\" to protect the MCP servers on this machine."));
      return;
    }
    servers.forEach(function (s) {
      var d = el("details", "server");
      d.open = !!openServers[s.server];
      d.addEventListener("toggle", function () { openServers[s.server] = d.open; });
      var summary = el("summary");
      summary.appendChild(el("span", "name", s.server));
      summary.appendChild(el("span", "meta", s.tools.length + (s.tools.length === 1 ? " tool" : " tools")));
      d.appendChild(summary);
      var body = el("div", "body");
      body.appendChild(el("div", "cmd", s.command));
      s.tools.forEach(function (t) {
        var row = el("div", "toolrow");
        row.appendChild(el("span", "tool", t.name));
        row.appendChild(el("span", "meta", t.description || "No description"));
        body.appendChild(row);
      });
      d.appendChild(body);
      root.appendChild(d);
    });
  }

  var BLOCKED = { call_blocked: 1, call_denied: 1, result_blocked: 1, flow_denied: 1, tool_changed: 1, tool_new: 1 };
  var WARNED = { call_warning: 1, result_warning: 1, definition_warning: 1 };
  var LABELS = {
    call: ["Call", "plain"], call_blocked: ["Blocked", "bad"], call_denied: ["Denied", "bad"],
    result_blocked: ["Output blocked", "bad"], flow_denied: ["Flow denied", "bad"],
    tool_changed: ["Tool changed", "bad"], tool_new: ["New tool", "bad"],
    call_warning: ["Warning", "warn"], result_warning: ["Output warning", "warn"], definition_warning: ["Warning", "warn"],
    flow: ["Data flow", "plain"], pinned: ["Approved", "ok"], tool_removed: ["Tool removed", "plain"], session_start: ["Started", "plain"]
  };

  function category(r) {
    if (BLOCKED[r.event]) return "blocked";
    if (WARNED[r.event] || (r.event === "flow" && r.warned)) return "warnings";
    if (r.event === "call") return "calls";
    return "other";
  }

  function detail(r) {
    switch (r.event) {
      case "call": return r.args === null || r.args === undefined ? "" : JSON.stringify(r.args);
      case "call_blocked": case "call_warning": case "result_warning": case "result_blocked": case "definition_warning":
        return (r.reason || "") + (r.rule ? " (rule " + r.rule + ")" : "");
      case "call_denied": return "It " + (r.reason || "broke a rule") + " (rule " + r.rule + ")";
      case "flow": case "flow_denied":
        return "Carried " + (r.kind === "secret" ? "a credential" : "a value") + " that came from " + r.from + (r.rule ? " (rule " + r.rule + ")" : "");
      case "tool_changed": return "Its definition no longer matches what you approved";
      case "tool_new": return "Appeared after the server was first approved";
      case "pinned": return r.count + (r.count === 1 ? " tool definition" : " tool definitions") + " recorded on first use";
      case "session_start": return (r.firstUse ? "First use" : "Session started") + ", " + r.mode + " mode";
      default: return "";
    }
  }

  function renderLog(records) {
    var root = $("log");
    root.textContent = "";
    var shown = records.filter(function (r) {
      // The per-tool "recorded" entries are summarized by the one first-use entry.
      if (r.event === "pinned" && r.tool) return false;
      return filter === "all" || category(r) === filter;
    }).slice(0, 200);
    if (shown.length === 0) {
      root.appendChild(el("div", "row", "Nothing to show yet."));
      return;
    }
    shown.forEach(function (r) {
      var row = el("div", "row");
      var t = el("time", null, new Date(r.ts).toLocaleTimeString());
      t.title = new Date(r.ts).toLocaleString();
      row.appendChild(t);
      var label = LABELS[r.event] || [r.event, "plain"];
      if (r.event === "flow" && r.warned) label = ["Credential moved", "warn"];
      var cell = el("div");
      cell.appendChild(el("span", "badge " + label[1], label[0]));
      row.appendChild(cell);
      var what = el("div", "what");
      what.appendChild(el("span", "where", r.server + (r.tool ? " / " + r.tool : "")));
      var d = detail(r);
      if (d) d = d.charAt(0).toUpperCase() + d.slice(1);
      if (d) what.appendChild(el("span", "detail", "  " + (d.length > 260 ? d.slice(0, 260) + "…" : d)));
      row.appendChild(what);
      root.appendChild(row);
    });
  }

  var latestRecords = [];

  function refresh() {
    return Promise.all([api("/api/state"), api("/api/log?limit=500")]).then(function (results) {
      var state = results[0];
      latestRecords = results[1].records;
      showError("");
      $("s-servers").textContent = state.servers.length;
      $("s-tools").textContent = state.servers.reduce(function (n, s) { return n + s.tools.length; }, 0);
      $("s-blocked").textContent = state.stats.blocked;
      $("s-calls").textContent = state.stats.calls;
      renderPending(state.servers);
      renderServers(state.servers);
      renderLog(latestRecords);
    }).catch(function (err) {
      showError(token ? err.message : "This page needs the link printed by \\"toolwarden dashboard\\" (it carries an access token).");
    });
  }

  $("filters").addEventListener("click", function (event) {
    var button = event.target.closest("button[data-filter]");
    if (!button) return;
    filter = button.getAttribute("data-filter");
    Array.prototype.forEach.call($("filters").querySelectorAll("button"), function (b) {
      b.setAttribute("aria-pressed", String(b === button));
    });
    renderLog(latestRecords);
  });

  refresh();
  setInterval(refresh, 3000);
})();
</script>
</body>
</html>
`;
