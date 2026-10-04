import { Database } from "bun:sqlite"
import { Effect, Schema } from "effect"
import { randomUUID } from "node:crypto"
import { chmodSync, mkdirSync } from "node:fs"
import { dirname, join } from "node:path"
import { Auth } from "./auth.js"
import { Op } from "./op.js"
import type { Binding } from "./request.js"

const fail = (message: string) => Op.fail(message)
const maxTtlSeconds = 60 * 60
const maxUses = 10

export interface StoreOptions {
  readonly path?: string
}

export interface GrantOptions extends StoreOptions {
  readonly expiresIn: string
  readonly uses: number
}

export interface ResourceVersion {
  readonly id: string
  readonly version: number
}

export interface ResolverDependencies {
  readonly inspect: (reference: string) => Effect.Effect<ResourceVersion, Op.Failure>
  readonly read: (reference: string) => Effect.Effect<string, Op.Failure>
}

interface LeaseRow {
  readonly id: string
  readonly principal: string
  readonly capability: string
  readonly method: string
  readonly reference: string
  readonly item_id: string
  readonly item_version: number
  readonly destination: string
  readonly destination_fingerprint: string
  readonly header: string
  readonly prefix: string
  readonly created_at: number
  readonly expires_at: number
  readonly use_budget: number
  readonly uses_remaining: number
  readonly revoked_at: number | null
}

const VersionedSummary = Schema.Struct({
  id: Op.Id,
  title: Schema.String,
  version: Schema.Number,
})

const decodePart = (value: string) => {
  try {
    return decodeURIComponent(value)
  } catch {
    throw fail("Secret reference is malformed")
  }
}

const referenceLocation = (reference: string) => {
  if (!reference.startsWith("op://") || /[\r\n?#]/.test(reference)) throw fail("Secret reference is malformed")
  const parts = reference.slice("op://".length).split("/")
  if (parts.length < 3 || parts.some((part) => part.length === 0)) throw fail("Secret reference is malformed")
  return { vault: decodePart(parts[0]!), item: decodePart(parts[1]!) }
}

export const inspectReference = Effect.fn("Lease.inspectReference")(function* (reference: string) {
  const { vault, item } = yield* Effect.try({
    try: () => referenceLocation(reference),
    catch: (error) => (error instanceof Op.Failure ? error : fail("Secret reference is malformed")),
  })
  // Use item-list metadata rather than item-get JSON. Current 1Password CLI
  // versions can include concealed field plaintext in JSON item-get output.
  const values = yield* Op.json(
    Schema.Array(VersionedSummary),
    ["item", "list", "--vault", vault, "--format", "json"],
    { failure: "Could not inspect credential version (1Password details suppressed)" },
  )
  const matches = values.filter((value) => value.id === item || value.title === item)
  const value = matches[0]
  if (matches.length !== 1 || value === undefined) {
    return yield* fail("Credential item must resolve to exactly one item for lease versioning")
  }
  if (!Number.isInteger(value.version) || value.version < 1) return yield* fail("1Password returned an invalid item version")
  return { id: value.id, version: value.version } satisfies ResourceVersion
})

const durationSeconds = (value: string) => {
  const match = /^([1-9]\d*)([smh])$/.exec(value)
  if (!match) throw fail("--expires-in must be a duration such as 10m or 1h")
  const count = Number(match[1])
  const multiplier = match[2] === "s" ? 1 : match[2] === "m" ? 60 : 3600
  const seconds = count * multiplier
  if (!Number.isSafeInteger(seconds) || seconds > maxTtlSeconds) {
    throw fail(`Lease lifetime cannot exceed ${maxTtlSeconds / 60} minutes`)
  }
  return seconds
}

const storePath = (override?: string) => {
  if (override) return override
  const home = process.env.HOME
  if (!home) throw fail("Could not locate the lease store")
  return join(home, ".config", "2password", "leases.sqlite")
}

const openDatabase = (override?: string) => {
  const path = storePath(override)
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const db = new Database(path, { create: true, strict: true })
  db.run("PRAGMA busy_timeout = 5000")
  db.run(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS leases (
      id TEXT PRIMARY KEY,
      principal TEXT NOT NULL,
      capability TEXT NOT NULL,
      method TEXT NOT NULL,
      reference TEXT NOT NULL,
      item_id TEXT NOT NULL,
      item_version INTEGER NOT NULL,
      destination TEXT NOT NULL,
      destination_fingerprint TEXT NOT NULL,
      header TEXT NOT NULL,
      prefix TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      use_budget INTEGER NOT NULL,
      uses_remaining INTEGER NOT NULL,
      revoked_at INTEGER
    );
  `)
  try {
    chmodSync(path, 0o600)
  } catch {}
  return db
}

const withDatabase = <A>(options: StoreOptions, operation: (db: Database) => A): Effect.Effect<A, Op.Failure> =>
  Effect.try({
    try: () => {
      const db = openDatabase(options.path)
      try {
        return operation(db)
      } finally {
        db.close()
      }
    },
    catch: (error) => (error instanceof Op.Failure ? error : fail("Lease store operation failed")),
  })

const principalOf = (db: Database): string => {
  const existing = db.query("SELECT value FROM meta WHERE key = 'principal'").get() as { value: string } | null
  if (existing) return existing.value
  const principal = randomUUID()
  db.query("INSERT OR IGNORE INTO meta (key, value) VALUES ('principal', ?)").run(principal)
  return (db.query("SELECT value FROM meta WHERE key = 'principal'").get() as { value: string }).value
}

const selectLease = (db: Database, id: string) =>
  db.query("SELECT * FROM leases WHERE id = ?").get(id) as LeaseRow | null

const matches = (row: LeaseRow, binding: Binding, principal: string, now: number) =>
  row.principal === principal &&
  row.capability === binding.capability &&
  row.method === binding.method &&
  row.reference === binding.reference &&
  row.destination === binding.destination &&
  row.destination_fingerprint === binding.destinationFingerprint &&
  row.header === binding.header &&
  row.prefix === binding.prefix &&
  row.revoked_at === null &&
  row.expires_at > now &&
  row.uses_remaining > 0

const receipt = (row: LeaseRow) => ({
  id: row.id,
  principal: row.principal,
  capability: row.capability,
  method: row.method,
  reference: row.reference,
  itemId: row.item_id,
  itemVersion: row.item_version,
  destination: row.destination,
  destinationFingerprint: row.destination_fingerprint,
  expiresAt: new Date(row.expires_at).toISOString(),
  useBudget: row.use_budget,
  usesRemaining: row.uses_remaining,
  revoked: row.revoked_at !== null,
})

export const grantWith = Effect.fn("Lease.grantWith")(function* (
  binding: Binding,
  options: GrantOptions,
  inspect: (reference: string) => Effect.Effect<ResourceVersion, Op.Failure>,
) {
  if (!Number.isInteger(options.uses) || options.uses < 1 || options.uses > maxUses) {
    return yield* fail(`--uses must be between 1 and ${maxUses}`)
  }
  const ttl = yield* Effect.try({
    try: () => durationSeconds(options.expiresIn),
    catch: (error) => (error instanceof Op.Failure ? error : fail("Invalid lease lifetime")),
  })
  const resource = yield* inspect(binding.reference)
  const now = Date.now()
  const id = randomUUID()
  return yield* withDatabase(options, (db) => {
    const principal = principalOf(db)
    db.query(
      `INSERT INTO leases (
        id, principal, capability, method, reference, item_id, item_version,
        destination, destination_fingerprint, header, prefix,
        created_at, expires_at, use_budget, uses_remaining, revoked_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    ).run(
      id,
      principal,
      binding.capability,
      binding.method,
      binding.reference,
      resource.id,
      resource.version,
      binding.destination,
      binding.destinationFingerprint,
      binding.header,
      binding.prefix,
      now,
      now + ttl * 1000,
      options.uses,
      options.uses,
    )
    return receipt(selectLease(db, id)!)
  })
})

export const grant = (binding: Binding, options: GrantOptions) =>
  process.stdin.isTTY && process.stderr.isTTY
    ? grantWith(binding, options, (reference) => inspectReference(reference).pipe(Auth.asDesktop))
    : Effect.fail(fail("Lease approval requires an interactive terminal"))

export const authorize = Effect.fn("Lease.authorize")(function* (
  id: string,
  binding: Binding,
  options: StoreOptions = {},
) {
  return yield* withDatabase(options, (db) => {
    const row = selectLease(db, id)
    const principal = principalOf(db)
    if (!row || !matches(row, binding, principal, Date.now())) {
      throw fail("Lease is invalid, expired, revoked, exhausted, or does not match this request")
    }
    return receipt(row)
  })
})

export const claim = Effect.fn("Lease.claim")(function* (
  id: string,
  binding: Binding,
  resource: ResourceVersion,
  options: StoreOptions = {},
) {
  return yield* withDatabase(options, (db) => {
    const principal = principalOf(db)
    const now = Date.now()
    const transaction = db.transaction(() => {
      const result = db.query(
        `UPDATE leases
         SET uses_remaining = uses_remaining - 1
         WHERE id = ?
           AND principal = ?
           AND capability = ?
           AND method = ?
           AND reference = ?
           AND item_id = ?
           AND item_version = ?
           AND destination = ?
           AND destination_fingerprint = ?
           AND header = ?
           AND prefix = ?
           AND revoked_at IS NULL
           AND expires_at > ?
           AND uses_remaining > 0`,
      ).run(
        id,
        principal,
        binding.capability,
        binding.method,
        binding.reference,
        resource.id,
        resource.version,
        binding.destination,
        binding.destinationFingerprint,
        binding.header,
        binding.prefix,
        now,
      )
      if (result.changes !== 1) {
        throw fail("Lease claim denied: expired, revoked, exhausted, stale, or mismatched")
      }
      return receipt(selectLease(db, id)!)
    })
    return transaction.immediate()
  })
})

export const resolverWith = (
  id: string,
  binding: Binding,
  options: StoreOptions,
  dependencies: ResolverDependencies,
): ((reference: string) => Effect.Effect<string, Op.Failure>) =>
  Effect.fn("Lease.resolverWith")(function* (reference: string) {
    if (reference !== binding.reference) return yield* fail("Lease does not match the requested credential")

    const before = yield* dependencies.inspect(reference)
    yield* claim(id, binding, before, options)

    const value = yield* dependencies.read(reference)
    const after = yield* dependencies.inspect(reference)
    if (after.id !== before.id || after.version !== before.version) {
      return yield* fail("Credential changed during leased use; the lease use was consumed and nothing was sent")
    }
    return value
  })

export const resolver = (
  id: string,
  binding: Binding,
  options: StoreOptions = {},
): ((reference: string) => Effect.Effect<string, Op.Failure>) =>
  resolverWith(id, binding, options, {
    inspect: inspectReference,
    read: (reference) =>
      Op.op(["read", reference], {
        failure: "Could not resolve leased credential (1Password details suppressed); the lease use was consumed",
      }),
  })

export const status = Effect.fn("Lease.status")(function* (id: string, options: StoreOptions = {}) {
  return yield* withDatabase(options, (db) => {
    const row = selectLease(db, id)
    if (!row) throw fail("Lease not found")
    return receipt(row)
  })
})

export const revoke = Effect.fn("Lease.revoke")(function* (id: string, options: StoreOptions = {}) {
  return yield* withDatabase(options, (db) => {
    const now = Date.now()
    const result = db.query("UPDATE leases SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(now, id)
    if (result.changes !== 1) throw fail("Lease not found or already revoked")
    return receipt(selectLease(db, id)!)
  })
})

export * as Lease from "./lease.js"
