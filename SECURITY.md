# Security policy

toolwarden is a security tool, so holes in it matter more than most bugs.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**
(<https://github.com/sarthakdev143-lite/toolwarden/security/advisories/new>).
If that is not available to you, use the contact address on the maintainer's GitHub profile.

Include what you did, what you expected, and what happened. A small MCP server or
config file that reproduces the problem helps most.

You can expect a first reply within a week. Once a fix is released you will be
credited in the release notes, unless you would rather not be.

## What counts

- A way for an MCP server to get a changed or new tool past pinning without approval
- A way to reach the server with a call that a deny rule should have stopped
- A way for a web page or another local user to read the audit log, approve a change,
  or use the HTTP proxy or dashboard
- A way for one operator account to read another account's state, or to use the hosted
  admin without that account's session
- Credentials ending up in the audit log, the flow files, or the dashboard
- Anything that makes `toolwarden init` damage a config file beyond what `--undo` restores

## What is a known limit, not a vulnerability

These are documented in the README and the [threat model](docs/threat-model.md):

- A first definition that does not match the hidden-instruction checks is trusted
- Pattern-based checks can be evaded by rewording
- In the default mode, suspicious text from a server is annotated, not withheld. That includes tool, resource, and prompt output and the other server messages
- Hosted sign-in is an email and a password stored by this process. There is no SSO vendor, no password-reset mail, and no payment provider
- Anyone who can open the hosted URL can create an account until `TOOLWARDEN_SIGNUP=closed`

Ideas for narrowing these limits are welcome as normal issues.

## Supported versions

Only the latest release gets fixes.
