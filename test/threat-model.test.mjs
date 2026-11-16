import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("threat-model table cells stay one sentence each", () => {
  const text = readFileSync(new URL("../docs/threat-model.md", import.meta.url), "utf8");
  const long = text.split("\n").filter((line) => line.length > 600);
  assert.deepEqual(
    long.map((line) => line.slice(0, 60)),
    [],
  );
  assert.match(text, /Partial: pattern matching on arguments/);
  assert.match(text, /Partial: pattern matching on text/);
  assert.match(text, /Partial: distinctive tokens only/);
  assert.match(text, /one layer of base64/);
  assert.doesNotMatch(text, /one list further past/);
});
