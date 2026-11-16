import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

test("the install guide states each behavior once", () => {
  const long = readme.split("\n").filter((line) => line.length > 1200);
  assert.deepEqual(
    long.map((line) => line.slice(0, 60)),
    [],
    "a feature or limit should fit on one readable line",
  );
  assert.match(readme, /calls to it are blocked until you review the change/);
  assert.match(readme, /denied before it reaches the server/);
  assert.match(readme, /treat it as data/);
  assert.match(readme, /nothing from the vault server may go to the web server/);
  assert.match(readme, /One layer of percent-encoding is decoded/);
  assert.match(readme, /Values encoded another way/);
  assert.match(readme, /Flow tracking follows distinctive tokens/);
  assert.match(readme, /`--results <mode>`/);
  assert.match(readme, /npm, pip, netrc, and git credentials/);
  assert.match(readme, /resource reads and subscriptions, filesystem roots, prompt and completion arguments/);
  assert.match(readme, /a later tool call, a resource read or subscription/);
  assert.match(readme, /toolwarden init --via <npx\\\|path>/);
  assert.match(readme, /`status`, `approve`, `log`, and `dashboard` use the same directory/);
  assert.match(readme, /Defaults to `<state>\/policy\.json`/);
  assert.match(readme, /not strict JSON, including one with comments/);
  assert.match(readme, /listed tools at connect time keeps a newly approved tool hidden until it reconnects/);
  assert.match(readme, /including an object key and one layer of percent-encoding or base64/);
  assert.doesNotMatch(readme, /when that output is not a list/);
  assert.doesNotMatch(readme, /padding left off/);
  assert.doesNotMatch(readme, /one list further past that further beyond/);

  const security = readFileSync(new URL("../SECURITY.md", import.meta.url), "utf8");
  assert.match(security, /suspicious text from a server is annotated, not withheld/);
  assert.match(security, /tool, resource, and prompt output and the other server messages/);
  assert.doesNotMatch(security, /suspicious tool output is annotated/);
});
