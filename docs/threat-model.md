# Threat model

What toolwarden is meant to stop, what it assumes, and where it stops helping.

## The setup

An AI app (the MCP client) connects to MCP servers. Each server offers tools. The model
reads every tool's name, description and input schema, decides which tools to call, and
reads what they return. The person using the app usually sees little of this.

toolwarden sits between the client and each server and sees every message in both
directions.

## What we protect

1. **The person's credentials and files**: SSH keys, cloud credentials, `.env` files, and token files such as Docker, GitHub CLI, GnuPG, Cargo, and Vault.
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
| The model is talked into reading credentials | Tool calls, resource URIs, resource subscriptions, filesystem roots, prompt arguments, completion arguments, other client messages, and answers to a server request that reference credential locations, including database password files, Terraform credentials, Kubernetes service-account tokens, rclone configs, and a path stored in a base64 blob or in image or audio data, are denied | Partial: pattern matching on arguments |
| A tool, resource or prompt result carries instructions | Results, structured tool output, tool errors, and text stored in a base64 resource blob or in image or audio data are scanned; a notice is added, or the text is withheld. Descriptions in resource, prompt, and resource-template listings are reported. A sampling request, a question the server asks the user, a log message the server sends, a progress update the server sends, a completion suggestion the server offers, a completion error the server returns, a cancellation the server sends, a resource update the server sends, any other notification the server sends, any other request the server sends, and the server's introduction are treated the same way | Partial: pattern matching on text |
| A secret read through one server is sent out through another | Values returned by a server, including text stored in a base64 blob or in image or audio data, and text in a log, a progress update, a sampling request, a question the server asks, a tool definition, the server's introduction, a completion suggestion, a completion error, a cancellation, a resource update, any other notification, any other server request, or a resource, prompt, or template description, are fingerprinted and recognized in calls, resource reads, resource subscriptions, filesystem roots, prompt arguments, completion arguments, any other client message, the answer to a server request, answers to another server's question, and the model's reply to a sampling request | Partial: distinctive tokens only |
| A web page calls the dashboard or proxy | Local-only listening, Host and Origin checks, a random token for the dashboard, a strict content security policy | Strong |
| A server's text attacks the dashboard itself | Server-supplied text is only ever written as text, never as HTML | Strong |

## What we assume

- **The machine and the user account are not already compromised.** Anything running as
  the same user can edit `~/.toolwarden` or the client's config and remove the firewall.
- **The MCP client honours what it is sent.** If the proxy hides a tool or returns an
  error, the client shows the model that, and does not reach the server some other way.
- **The first listing is reviewed or at least plausible.** See below.

## Known limits

**The first version of a tool is trusted.** Pinning detects change; it cannot tell that a
definition was malicious from the start. The definition checks flag common tricks, but
they warn and do not block. That first listing can span pages, but only along the cursor
the server just issued, and only for 32 pages. A server that always advertises another
page does not keep the first-use window open, and a call to a tool that was never listed
is blocked.

**Pattern checks can be evaded.** One layer of percent-encoding is decoded before the
checks, and one layer of base64 is decoded for a resource blob and for image and audio data. A determined attacker
can encode another way, split or reword. The argument rules, result checks and flow
tracking raise the cost of an attack and catch the common forms; they are not a proof
of safety.

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
  including one layer of percent-encoding or base64, and flow tracking keeps only hashes.
- **Fail closed where it is safe to.** A changed tool is blocked until someone decides.
