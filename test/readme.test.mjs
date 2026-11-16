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
  assert.doesNotMatch(readme, /one list further past that further beyond/);
});
