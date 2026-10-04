import { Effect, Schema } from "effect"
import { Auth } from "./auth.js"
import { LeaseStore, type ResourceVersion, type StoreOptions } from "./lease-store.js"
import { Op } from "./op.js"
import type { Binding } from "./request.js"

const fail = (message: string) => Op.fail(message)
const maxTtlSeconds = 60 * 60
const maxUses = 10

export interface GrantOptions extends StoreOptions {
  readonly expiresIn: string
  readonly uses: number
}

export interface ResolverDependencies {
  readonly inspect: (reference: string) => Effect.Effect<ResourceVersion, Op.Failure>
  readonly read: (reference: string) => Effect.Effect<string, Op.Failure>
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

  // Stay on metadata-only item list. JSON item-get may contain concealed values.
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
  if (!Number.isInteger(value.version) || value.version < 1) {
    return yield* fail("1Password returned an invalid item version")
  }
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
  return yield* LeaseStore.grant(binding, resource, {
    path: options.path,
    uses: options.uses,
    expiresAt: Date.now() + ttl * 1000,
  })
})

export const grant = (binding: Binding, options: GrantOptions) =>
  process.stdin.isTTY && process.stderr.isTTY
    ? grantWith(binding, options, (reference) => inspectReference(reference).pipe(Auth.asDesktop))
    : Effect.fail(fail("Lease approval requires an interactive terminal"))

export const resolverWith = (
  id: string,
  binding: Binding,
  options: StoreOptions,
  dependencies: ResolverDependencies,
): ((reference: string) => Effect.Effect<string, Op.Failure>) =>
  Effect.fn("Lease.resolverWith")(function* (reference: string) {
    if (reference !== binding.reference) return yield* fail("Lease does not match the requested credential")

    const before = yield* dependencies.inspect(reference)
    yield* LeaseStore.claim(id, binding, before, options)

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

export const authorize = LeaseStore.authorize
export const status = LeaseStore.status
export const revoke = LeaseStore.revoke

export * as Lease from "./lease.js"
