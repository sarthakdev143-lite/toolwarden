import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";

/**
 * Operator accounts for the hosted service.
 *
 * Each account gets a state directory named from its own id under TOOLWARDEN_DATA.
 * That directory is never the local CLI default (~/.toolwarden), so two accounts
 * cannot share one state directory by being left on the default. Passwords are
 * scrypt hashes. A session is a random id stored here. The browser cannot unpack
 * it, and it is not the OAuth pass-through a remote MCP server uses.
 */

const SESSION_MS = 14 * 24 * 60 * 60 * 1000;
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;
const KEY_LEN = 32;

export class AccountError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "AccountError";
    this.status = status;
  }
}

export interface PublicAccount {
  id: string;
  email: string;
  createdAt: string;
  stateDir: string;
}

interface StoredAccount extends PublicAccount {
  passwordHash: string;
  passwordSalt: string;
}

interface StoredSession {
  id: string;
  accountId: string;
  createdAt: string;
  expiresAt: string;
}

interface SessionIssue {
  id: string;
  maxAgeSeconds: number;
}

export function cliStateDir(): string {
  return process.env.TOOLWARDEN_HOME ?? join(homedir(), ".toolwarden");
}

export function defaultDataDir(): string {
  return process.env.TOOLWARDEN_DATA ?? join(homedir(), ".toolwarden-data");
}

function hashPassword(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LEN, SCRYPT);
}

let dummy: { salt: Buffer; hash: Buffer } | null = null;

/** One scrypt for an unknown email, so a missing account does not return faster than a wrong password. */
function dummyMaterial(): { salt: Buffer; hash: Buffer } {
  if (!dummy) {
    const salt = Buffer.alloc(16, 7);
    dummy = { salt, hash: hashPassword("toolwarden-not-a-password", salt) };
  }
  return dummy;
}

function sameSecret(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function validEmail(email: string): boolean {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function expectedStateDir(dataDir: string, id: string): string {
  return resolve(dataDir, "accounts", id, "state");
}

function overlaps(a: string, b: string): boolean {
  const left = resolve(a);
  const right = resolve(b);
  return left === right || left.startsWith(right + sep) || right.startsWith(left + sep);
}

function writePrivate(path: string, text: string): void {
  const tmp = path + "." + process.pid + ".tmp";
  writeFileSync(tmp, text, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  chmodSync(path, 0o600);
}

function toPublic(account: StoredAccount): PublicAccount {
  return {
    id: account.id,
    email: account.email,
    createdAt: account.createdAt,
    stateDir: account.stateDir,
  };
}

export class AccountStore {
  constructor(
    private readonly dataDir: string,
    private readonly now: () => Date = () => new Date(),
  ) {
    const cli = cliStateDir();
    if (overlaps(dataDir, cli)) {
      throw new Error(
        `TOOLWARDEN_DATA (${resolve(dataDir)}) overlaps the local CLI state directory (${resolve(cli)}). Use a separate directory so accounts do not share it.`,
      );
    }
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  }

  signup(email: string, password: string): PublicAccount {
    const normalized = normalizeEmail(email);
    if (!validEmail(normalized)) throw new AccountError("Enter an email address.", 400);
    if (password.length < 8) throw new AccountError("Use a password of at least 8 characters.", 400);
    if (password.length > 200) throw new AccountError("Use a password of at most 200 characters.", 400);

    const accounts = this.readAccounts();
    if (accounts.some((account) => account.email === normalized)) {
      throw new AccountError("An account with that email already exists.", 409);
    }

    const id = randomBytes(16).toString("hex");
    const salt = randomBytes(16);
    const stateDir = expectedStateDir(this.dataDir, id);
    const createdAt = this.now().toISOString();
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    writePrivate(join(stateDir, "account.json"), JSON.stringify({ id, email: normalized }) + "\n");
    const stored: StoredAccount = {
      id,
      email: normalized,
      createdAt,
      stateDir,
      passwordSalt: salt.toString("hex"),
      passwordHash: hashPassword(password, salt).toString("hex"),
    };
    accounts.push(stored);
    this.writeAccounts(accounts);
    return toPublic(stored);
  }

  authenticate(email: string, password: string): PublicAccount | null {
    const normalized = normalizeEmail(email);
    const account = this.readAccounts().find((item) => item.email === normalized);
    if (!account) {
      const unused = dummyMaterial();
      sameSecret(hashPassword(password, unused.salt), unused.hash);
      return null;
    }
    const actual = hashPassword(password, Buffer.from(account.passwordSalt, "hex"));
    const expected = Buffer.from(account.passwordHash, "hex");
    if (!sameSecret(actual, expected)) return null;
    return toPublic(account);
  }

  findByEmail(email: string): PublicAccount | null {
    const normalized = normalizeEmail(email);
    const account = this.readAccounts().find((item) => item.email === normalized);
    return account ? toPublic(account) : null;
  }

  createSession(accountId: string): SessionIssue {
    const accounts = this.readAccounts();
    if (!accounts.some((account) => account.id === accountId)) {
      throw new AccountError("That account does not exist.", 404);
    }
    const sessions = this.readSessions();
    const created = this.now();
    const session: StoredSession = {
      id: randomBytes(32).toString("base64url"),
      accountId,
      createdAt: created.toISOString(),
      expiresAt: new Date(created.getTime() + SESSION_MS).toISOString(),
    };
    sessions.push(session);
    this.writeSessions(sessions);
    return { id: session.id, maxAgeSeconds: Math.floor(SESSION_MS / 1000) };
  }

  accountForSession(sessionId: string): PublicAccount | null {
    if (sessionId === "") return null;
    const accounts = this.readAccounts();
    const sessions = this.readSessions();
    const session = sessions.find((item) => item.id === sessionId);
    if (!session) return null;
    if (Date.parse(session.expiresAt) <= this.now().getTime()) {
      this.writeSessions(sessions.filter((item) => item.id !== sessionId));
      return null;
    }
    const account = accounts.find((item) => item.id === session.accountId);
    return account ? toPublic(account) : null;
  }

  destroySession(sessionId: string): void {
    const sessions = this.readSessions();
    this.writeSessions(sessions.filter((item) => item.id !== sessionId));
  }

  private accountsPath(): string {
    return join(this.dataDir, "accounts.json");
  }

  private sessionsPath(): string {
    return join(this.dataDir, "sessions.json");
  }

  private readAccounts(): StoredAccount[] {
    if (!existsSync(this.accountsPath())) return [];
    const parsed = JSON.parse(readFileSync(this.accountsPath(), "utf8")) as { accounts?: unknown };
    if (!parsed || !Array.isArray(parsed.accounts)) throw new Error("accounts.json is damaged");
    const seen = new Set<string>();
    return parsed.accounts.map((item) => this.checkAccount(item, seen));
  }

  private checkAccount(item: unknown, seen: Set<string>): StoredAccount {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("an account record is damaged");
    }
    const record = item as Record<string, unknown>;
    const id = record.id;
    const email = record.email;
    const stateDir = record.stateDir;
    const passwordHash = record.passwordHash;
    const passwordSalt = record.passwordSalt;
    const createdAt = record.createdAt;
    if (typeof id !== "string" || !/^[a-f0-9]{32}$/.test(id)) throw new Error("an account id is damaged");
    if (typeof email !== "string" || email !== normalizeEmail(email) || !validEmail(email)) {
      throw new Error("an account email is damaged");
    }
    if (typeof stateDir !== "string" || resolve(stateDir) !== expectedStateDir(this.dataDir, id)) {
      throw new Error(`account ${id} does not use its own state directory`);
    }
    if (seen.has(id)) throw new Error("two accounts share a state directory");
    seen.add(id);
    if (typeof passwordHash !== "string" || !/^[a-f0-9]{64}$/.test(passwordHash)) {
      throw new Error("an account record is damaged");
    }
    if (typeof passwordSalt !== "string" || !/^[a-f0-9]{32}$/.test(passwordSalt)) {
      throw new Error("an account record is damaged");
    }
    if (typeof createdAt !== "string" || createdAt === "") throw new Error("an account record is damaged");
    return { id, email, stateDir: resolve(stateDir), passwordHash, passwordSalt, createdAt };
  }

  private readSessions(): StoredSession[] {
    if (!existsSync(this.sessionsPath())) return [];
    const parsed = JSON.parse(readFileSync(this.sessionsPath(), "utf8")) as { sessions?: unknown };
    if (!parsed || !Array.isArray(parsed.sessions)) throw new Error("sessions.json is damaged");
    return parsed.sessions.map((item) => {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new Error("a session record is damaged");
      }
      const record = item as Record<string, unknown>;
      if (
        typeof record.id !== "string" ||
        record.id === "" ||
        typeof record.accountId !== "string" ||
        typeof record.createdAt !== "string" ||
        typeof record.expiresAt !== "string"
      ) {
        throw new Error("a session record is damaged");
      }
      return {
        id: record.id,
        accountId: record.accountId,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
      };
    });
  }

  private writeAccounts(accounts: StoredAccount[]): void {
    writePrivate(this.accountsPath(), JSON.stringify({ accounts }, null, 2) + "\n");
  }

  private writeSessions(sessions: StoredSession[]): void {
    writePrivate(this.sessionsPath(), JSON.stringify({ sessions }, null, 2) + "\n");
  }
}
