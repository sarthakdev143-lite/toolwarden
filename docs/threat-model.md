# Threat model

What toolwarden is meant to stop, what it assumes, and where it stops helping.

## The setup

An AI app (the MCP client) connects to MCP servers. Each server offers tools. The model
reads every tool's name, description and input schema, decides which tools to call, and
reads what they return. The person using the app usually sees little of this.

toolwarden sits between the client and each server and sees every message in both
directions.

## What we protect

1. **The person's credentials and files**: SSH keys, cloud credentials, `.env` files, and token files such as npm, pip, netrc, git credentials, Docker, the GitHub CLI, GnuPG, Cargo, Vault, database passwords, Terraform, a Kubernetes service account, and rclone.
2. **The model's instructions**: what the model does should come from the person, not
   from text a server slipped in.
3. **The person's ability to know what happened**: a record of every tool call.

## Who we defend against

**A malicious or compromised MCP server.** It controls its tool definitions and its tool
results, and it can change either at any time. This covers a server that was honest when
installed and turned later (a rug-pull), whether through its author, a hijacked package
update, or a compromised remote host.

**Poisoned content passing through an honest server.** A web page, document, issue or
email that an honest tool fetches can contain instructions aimed at the model.

**A web page in the person's browser.** It can send requests to `127.0.0.1`, so it could
try to reach the dashboard or the HTTP proxy.

## What toolwarden does about each

| Attack | Defence | Strength |
|---|---|---|
| A tool's definition changes after approval | Definitions are hashed on first use; a changed tool is hidden and its calls are blocked until approved | Strong: any change to the definition is detected |
| A review approves a definition that changed again | The dashboard pins a tool only when its hash is still the one on the page; otherwise the whole request is refused | Strong |
| A new tool appears later | It is quarantined until approved | Strong |
| The model is talked into reading credentials | Tool calls and other client or server messages that reference SSH keys, cloud credentials, `.env` files, or token files are denied. That includes resource reads, subscriptions, filesystem roots, prompt and completion arguments, answers, sampling replies, object keys, and a path in one layer of base64 or in image or audio data. | Partial: pattern matching on arguments |
| A tool, resource or prompt result carries instructions | Results, errors, structured output, resource blobs, image and audio data, and other text a server sends are scanned, including one layer of base64 and text written with a compatibility or invisible character. A notice is added, or the text is withheld. Sampling requests, questions, logs, progress, completions, cancellations, resource updates, and the server's introduction are treated the same way. | Partial: pattern matching on text |
| A secret read through one server is sent out through another | Values a server returns or shows, including one layer of base64, image or audio data, object keys, and text written with a compatibility or invisible character, are fingerprinted and recognized in a later call to another server. | Partial: distinctive tokens only |
| A web page calls the dashboard or proxy | Local-only listening, Host and Origin checks, a random token for the dashboard, a strict content security policy | Strong |
| A server's text attacks the dashboard itself | Server-supplied text is only ever written as text, never as HTML | Strong |

## What we assume

- **The machine and the user account are not already compromised.** Anything running as
  the same user can edit `~/.toolwarden` or the client's config and remove the firewall.
- **The MCP client honours what it is sent.** If the proxy hides a tool or returns an
  error, the client shows the model that, and does not reach the server some other way.
- **The first listing is reviewed or at least plausible.** See below.

## Known limits

**A clean first listing is the baseline.** Pinning detects change. A first definition
that matches a hidden-instruction check is hidden until someone reviews it. A first
definition that does not match those checks is still trusted, so a reworded instruction
can still get through on day one. That first listing can span pages, but only along the
cursor the server just issued, and only for 32 pages. A server that always advertises
another page does not keep the first-use window open, and a call to a tool that was
never listed is blocked.

**Pattern checks can be evaded by rewording.** One layer of percent-encoding is decoded
before the checks, and one layer of base64 is decoded too, including URL-safe and
unpadded text, text written with a compatibility or invisible character, and text nested
in a list or object. One layer of HTML character references and of `\u` or `\x` escapes
is decoded too. Look-alike letters are folded, and text split by separators or across
adjacent strings in a list is joined before the check. A phrase that is reworded, or
built by the server without sending the text, can still get past them. The argument
rules, result checks and flow tracking raise the cost of an attack and catch the common
forms; they are not a proof of safety.

**A server acts with whatever access it was given.** toolwarden governs what passes
through the protocol. A local server that reads `~/.ssh` by itself, without being asked
through a tool call, is not something a protocol proxy can see. Give servers the least
access they need.

**Annotating is advice.** In the default mode a suspicious result still reaches the model,
with a notice in front. A model can still be fooled. `--results block` withholds it.

**The audit log is local and editable.** It is a record for the person, not tamper-proof
evidence.

**`toolwarden approve` pins what is waiting when it runs.** The dashboard will not pin
a version you did not see. A listing that arrives between `toolwarden status` and
`toolwarden approve` can be the version that gets pinned. Use the dashboard when the
tool may still be changing.

## Design choices that follow from this

- **No runtime dependencies.** A firewall that pulls in a large dependency tree is itself
  a supply-chain risk.
- **`init --via npx` pins an exact version.** The tool that guards against silent changes
  does not update itself silently.
- **Nothing leaves the machine.** No telemetry and no network calls of its own.
- **Secrets are not stored.** Credential-shaped values are removed from the audit log,
  including an object key, a value written with a compatibility or invisible character, and one layer of percent-encoding or base64. Flow tracking keeps only hashes.
- **Fail closed where it is safe to.** A changed tool is blocked until someone decides.

## Hosted operator sign-in

`npm start` stores accounts and sessions in `TOOLWARDEN_DATA` on the machine that runs it.
It does not send telemetry. The session is an email and a password for this process.
It is separate from OAuth that a remote MCP server asks the MCP client to complete.
When `TOOLWARDEN_MCP_URL` is set, `/mcp` forwards a signed-in account to that server
and writes pins in that account's state directory. The session is not sent upstream.
The pattern checks are the same checks as the local CLI. They do not stop every attack.
