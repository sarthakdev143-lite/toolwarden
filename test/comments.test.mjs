import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const files = ["src/scan.ts", "src/firewall.ts", "src/flow.ts", "src/policy.ts"];

test("scan comments name the behavior once", () => {
  for (const file of files) {
    const text = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    const long = text.split("\n").filter((line) => line.length > 1200);
    assert.deepEqual(
      long.map((line) => line.slice(0, 60)),
      [],
      file,
    );
    assert.doesNotMatch(text, /one list further past/);
  }
  const flow = readFileSync(new URL("../src/flow.ts", import.meta.url), "utf8");
  assert.match(flow, /hashes, never the values/);
  assert.match(flow, /progress token and a message id are left unchanged/);
});
