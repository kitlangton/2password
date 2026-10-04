import { Database } from "bun:sqlite"
import { Effect } from "effect"
import { randomUUID } from "node:crypto"
import { chmodSync, mkdirSync } from "node:fs"
import { dirname, join } from "node:path"
import { Op } from "./op.js"
import type { Binding } from "./request.js"

const fail = (message: string) => Op.fail(message)

export interface ResourceVersion {
  readonly id: string
  readonly version: number
}

export interface StoreOptions {
  readonly path?: string
}

export interface GrantOptions extends StoreOptions {
  readonly expiresAt: number
  readonly uses: number
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

const storePath = (override?: string) => {
  if (override) return override
  const home = process.env.HOME ?? process.env.USERPROFILE
  if (!home) throw fail("Could not locate the lease store")
  return join(home, ".config", "2password", "leases.sqlite")
}

const openDatabase = (override?: string) => {
  const path = storePath(override)
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const db = new Database(path, { create: true, strict: true })
  db.exec("PRAGMA busy_timeout = 5000")
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `)
  db.exec(`
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
    )
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
  const stored = db.query("SELECT value FROM meta WHERE key = 'principal'").get() as { value: string } | null
  if (!stored) throw fail("Could not initialize local principal")
  return stored.value
}

const selectLease = (db: Database, id: string) =>
  db.query("SELECT * FROM leases WHERE id = ?").get(id) as LeaseRow | null

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
  header: row.header,
  prefix: row.prefix,
  createdAt: new Date(row.created_at).toISOString(),
  expiresAt: new Date(row.expires_at).toISOString(),
  useBudget: row.use_budget,
  usesRemaining: row.uses_remaining,
  revoked: row.revoked_at !== null,
})

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

export const grant = Effect.fn("LeaseStore.grant")(function* (
  binding: Binding,
  resource: ResourceVersion,
  options: GrantOptions,
) {
  const now = Date.now()
  if (
    !Number.isInteger(options.uses) ||
    options.uses < 1 ||
    !Number.isSafeInteger(options.expiresAt) ||
    options.expiresAt <= now ||
    !Number.isInteger(resource.version) ||
    resource.version < 1
  ) {
    return yield* fail("Invalid lease grant")
  }
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
      options.expiresAt,
      options.uses,
      options.uses,
    )
    const row = selectLease(db, id)
    if (!row) throw fail("Lease creation was not persisted")
    return receipt(row)
  })
})

export const authorize = Effect.fn("LeaseStore.authorize")(function* (
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

export const claim = Effect.fn("LeaseStore.claim")(function* (
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
      const row = selectLease(db, id)
      if (!row) throw fail("Lease disappeared after claim")
      return receipt(row)
    })
    return transaction.immediate()
  })
})

export const status = Effect.fn("LeaseStore.status")(function* (id: string, options: StoreOptions = {}) {
  return yield* withDatabase(options, (db) => {
    const row = selectLease(db, id)
    if (!row) throw fail("Lease not found")
    return receipt(row)
  })
})

export const revoke = Effect.fn("LeaseStore.revoke")(function* (id: string, options: StoreOptions = {}) {
  return yield* withDatabase(options, (db) => {
    const now = Date.now()
    const result = db.query("UPDATE leases SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(now, id)
    if (result.changes !== 1) throw fail("Lease not found or already revoked")
    const row = selectLease(db, id)
    if (!row) throw fail("Lease disappeared after revocation")
    return receipt(row)
  })
})

export * as LeaseStore from "./lease-store.js"
