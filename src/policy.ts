import { existsSync, readFileSync } from "node:fs";
import { collectText, matchForms } from "./scan.js";

export interface Rule {
  id: string;
  /** Glob over the tool name. "*" matches anything, including a line break. Defaults to "*". */
  tool?: string;
  /** Regular expression (case-insensitive) tested against every string in the call, other than a tool call's name, including object keys and text stored in a base64 blob (URL-safe, unpadded, or written with a compatibility or invisible character), including when that blob is a list or an object, including an object in that list and an object inside that object, and an object inside that blob object, including an object inside that one, and in a list in that blob object, including a list in that list, including a list in that one, including a list in that one as well, including a list beyond that, including one list past that, or in image and audio data, including when that data is a list or an object, including an object in that list and an object inside that object, and an object inside that data object, including an object inside that one, and in a list in that data object, including a list in that list, including a list in that one, including a list in that one as well, including a list beyond that, including one list past that. Percent-encoding, compatibility characters, and invisible characters are folded before the test. */
  pattern: string;
  /** "deny" blocks the call. "warn" lets it through and records a warning. Defaults to "deny". */
  action?: "deny" | "warn";
  message?: string;
}

/** A rule about data moving from one server to another. */
export interface FlowRule {
  id: string;
  /** Glob over the server the data came from. Defaults to "*". */
  from?: string;
  /** Glob over the server the data is going to. Defaults to "*". */
  to?: string;
  /** "secret" matches only credential-shaped values. "any" (default) matches every tracked value. */
  kind?: "secret" | "any";
  /** "deny" blocks the call. "warn" reports it. "allow" silences the default warning. */
  action: "deny" | "warn" | "allow";
}

export interface PolicyFile {
  /** Set to false to turn off the built-in rules. */
  defaultRules?: boolean;
  rules?: Rule[];
  flows?: FlowRule[];
}

/** "=" is not a path edge, so a search for the text ".env" stays allowed. */
const PATH_EDGE = "(^|[\\\\/\\s'\"`])";

export const DEFAULT_RULES: Rule[] = [
  {
    id: "ssh-keys",
    pattern: PATH_EDGE + "\\.ssh($|[^\\w.-])|\\bid_(rsa|ed25519|ecdsa|dsa)\\b",
    message: "references SSH keys",
  },
  {
    id: "cloud-credentials",
    pattern: PATH_EDGE + "\\.(aws|azure|kube)($|[^\\w.-])|\\.config[\\\\/]gcloud($|[^\\w.-])",
    message: "references cloud credentials",
  },
  {
    id: "env-files",
    pattern: PATH_EDGE + "\\.env(\\.[\\w.-]+)?($|[^\\w.-])",
    message: "references a .env file",
  },
  {
    id: "package-tokens",
    pattern: PATH_EDGE + "\\.(npmrc|pypirc|netrc|git-credentials)($|[^\\w.-])",
    message: "references a file that stores access tokens",
  },
  {
    id: "docker-credentials",
    pattern: PATH_EDGE + "\\.docker($|[^\\w.-])",
    message: "references Docker credentials",
  },
  {
    id: "gh-credentials",
    pattern: PATH_EDGE + "\\.config[\\\\/]gh($|[^\\w.-])",
    message: "references GitHub CLI credentials",
  },
  {
    id: "gnupg-keys",
    pattern: PATH_EDGE + "\\.gnupg($|[^\\w.-])",
    message: "references GnuPG keys",
  },
  {
    id: "cargo-credentials",
    pattern: PATH_EDGE + "\\.cargo[\\\\/]credentials(\\.toml)?($|[^\\w.-])",
    message: "references Cargo registry credentials",
  },
  {
    id: "vault-token",
    pattern: PATH_EDGE + "\\.vault-token($|[^\\w.-])",
    message: "references a Vault token",
  },
  {
    id: "database-passwords",
    pattern: PATH_EDGE + "\\.(pgpass|mylogin\\.cnf|my\\.cnf)($|[^\\w.-])",
    message: "references a database password file",
  },
  {
    id: "terraform-credentials",
    pattern: PATH_EDGE + "\\.terraformrc($|[^\\w.-])|\\.terraform\\.d($|[^\\w.-])|" + PATH_EDGE + "credentials\\.tfrc\\.json($|[^\\w.-])",
    message: "references Terraform credentials",
  },
  {
    id: "kube-serviceaccount",
    pattern: "secrets[\\\\/]kubernetes\\.io[\\\\/]serviceaccount($|[^\\w.-])",
    message: "references a Kubernetes service account token",
  },
  {
    id: "rclone-credentials",
    pattern: PATH_EDGE + "\\.config[\\\\/]rclone($|[^\\w.-])|" + PATH_EDGE + "rclone\\.conf($|[^\\w.-])",
    message: "references rclone credentials",
  },
];

interface CompiledRule {
  rule: Rule;
  tool: RegExp;
  pattern: RegExp;
}

/** `*` matches any text, including a line break, so a name cannot step around a rule by containing one. */
function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[\\s\\S]*");
  return new RegExp("^" + escaped + "$");
}

export interface Verdict {
  denied: { ruleId: string; message: string } | null;
  warnings: { ruleId: string; message: string }[];
}

interface CompiledFlowRule {
  rule: FlowRule;
  from: RegExp;
  to: RegExp;
}

export class Policy {
  private readonly compiled: CompiledRule[];
  private readonly flows: CompiledFlowRule[];

  constructor(rules: Rule[], flows: FlowRule[] = []) {
    this.flows = flows.map((rule) => ({
      rule,
      from: globToRegExp(rule.from ?? "*"),
      to: globToRegExp(rule.to ?? "*"),
    }));
    this.compiled = rules.map((rule) => {
      let pattern: RegExp;
      try {
        pattern = new RegExp(rule.pattern, "i");
      } catch (err) {
        throw new Error(`policy rule "${rule.id}" has an invalid pattern: ${(err as Error).message}`);
      }
      return { rule, tool: globToRegExp(rule.tool ?? "*"), pattern };
    });
  }

  get ruleCount(): number {
    return this.compiled.length;
  }

  /**
   * What to do about data from server `from` appearing in a call to server `to`.
   * The first matching rule wins. With no matching rule, credential-shaped
   * values are reported and everything else is only logged.
   */
  evaluateFlow(from: string, to: string, kind: "secret" | "value"): { action: "deny" | "warn" | "log"; ruleId: string | null } {
    for (const f of this.flows) {
      if ((f.rule.kind ?? "any") === "secret" && kind !== "secret") continue;
      if (!f.from.test(from) || !f.to.test(to)) continue;
      return { action: f.rule.action === "allow" ? "log" : f.rule.action, ruleId: f.rule.id };
    }
    return { action: kind === "secret" ? "warn" : "log", ruleId: null };
  }

  evaluate(toolName: string, args: unknown): Verdict {
    const candidates = collectText(args).flatMap(matchForms);
    const verdict: Verdict = { denied: null, warnings: [] };
    for (const c of this.compiled) {
      if (!c.tool.test(toolName)) continue;
      if (!candidates.some((s) => c.pattern.test(s))) continue;
      const hit = { ruleId: c.rule.id, message: c.rule.message ?? `matched rule ${c.rule.id}` };
      if ((c.rule.action ?? "deny") === "deny") {
        verdict.denied ??= hit;
      } else {
        verdict.warnings.push(hit);
      }
    }
    return verdict;
  }
}

/** Load a policy file if given (or present), and combine it with the built-in rules. */
export function loadPolicy(path: string | null, useDefaults: boolean): Policy {
  let file: PolicyFile = {};
  if (path !== null) {
    if (!existsSync(path)) throw new Error(`policy file not found: ${path}`);
    file = JSON.parse(readFileSync(path, "utf8")) as PolicyFile;
  }
  const rules: Rule[] = [];
  if (useDefaults && file.defaultRules !== false) rules.push(...DEFAULT_RULES);
  for (const r of file.rules ?? []) {
    if (typeof r.id !== "string" || typeof r.pattern !== "string") {
      throw new Error("each policy rule needs a string \"id\" and \"pattern\"");
    }
    rules.push(r);
  }
  for (const f of file.flows ?? []) {
    if (typeof f.id !== "string" || !["deny", "warn", "allow"].includes(f.action)) {
      throw new Error('each flow rule needs a string "id" and an "action" of deny, warn or allow');
    }
  }
  return new Policy(rules, file.flows ?? []);
}
