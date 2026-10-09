import { Effect, Redacted, Schema } from "effect"
import { Auth } from "./auth.js"
import { Create } from "./create.js"
import { Op } from "./op.js"

const manageUrl = "https://start.1password.com/developer-tools/active"
const builtInVaults = ["personal", "private", "employee", "shared"]
const { fail } = Op

// Administrative operations always use desktop authentication.
const admin = <S extends Schema.Constraint>(
  schema: S,
  args: ReadonlyArray<string>,
  account: string | undefined,
  failure: string,
) => Op.json(schema, args, { account, failure }).pipe(Auth.asDesktop)

const parseToken = (raw: string) => {
  const token = raw.replace(/\r?\n$/, "")
  return /^ops_[^\s]+$/.test(token)
    ? Effect.succeed(Redacted.make(token))
    : Effect.fail(fail("No valid service-account token was received (details suppressed)"))
}

export interface SetupOptions {
  readonly name: string
  readonly vault: ReadonlyArray<string>
  readonly saveVault: string
  readonly account?: string | undefined
  readonly createVault: boolean
  readonly write: boolean
  readonly expiresIn?: string | undefined
}

// Every remote step is checked before the next; a once-returned token is saved
// before anything else can fail, so partial setups are recoverable, never retried.
export const setup = Effect.fn("ServiceAccount.setup")(function* (options: SetupOptions) {
  const name = options.name.trim()
  const vaultNames = options.vault.map((vault) => vault.trim())
  const saveVault = options.saveVault.trim()
  const { account } = options
  if (
    !name ||
    vaultNames.length === 0 ||
    vaultNames.some((vault) => !vault) ||
    !saveVault ||
    name.startsWith("-") ||
    vaultNames.some((vault) => vault.startsWith("-")) ||
    /[\r\n]/.test(name + vaultNames.join("") + saveVault)
  ) {
    return yield* fail("A non-empty account name, automation vault, and backup vault are required")
  }
  if (new Set(vaultNames).size !== vaultNames.length) {
    return yield* fail("Automation vaults must be unique")
  }
  if (vaultNames.some((vault) => builtInVaults.includes(vault.toLowerCase()))) {
    return yield* fail(
      "Choose a dedicated automation vault; built-in personal/shared vaults cannot be granted to service accounts",
    )
  }
  if (options.expiresIn !== undefined && !/^[1-9]\d*[smhdw]$/.test(options.expiresIn)) {
    return yield* fail("--expires-in must be a positive duration such as 90d")
  }
  yield* Auth.requireEmpty

  const vaults = yield* admin(
    Schema.Array(Auth.Vault),
    ["vault", "list", "--format", "json"],
    account,
    "Could not read administrator vault metadata; nothing was created",
  )
  const select = (value: string) => vaults.filter((vault) => vault.id === value || vault.name === value)
  const backups = select(saveVault)
  const backup = backups[0]
  if (backups.length !== 1 || backup === undefined)
    return yield* fail("The backup vault must resolve to one existing vault; nothing was created")
  const title = `1Password ${name} Service Account Token`
  const backupCheckFailure = "Could not check the token backup destination; nothing was created"
  if (yield* Create.titleTaken(backup.id, title, account, backupCheckFailure).pipe(Auth.asDesktop)) {
    return yield* fail(
      "A token backup with this title already exists; inspect it before creating another service account",
    )
  }

  const requested = yield* Effect.forEach(vaultNames, (vaultName) => {
    const matches = select(vaultName)
    if (matches.length > 1) return fail("Automation vault name is ambiguous; specify its ID")
    const existing = matches[0]
    if (existing) return Effect.succeed(existing)
    if (!options.createVault) return fail("An automation vault does not exist; use --create-vault to create it")
    return Effect.succeed({ id: "", name: vaultName })
  })
  const resolved: Array<typeof Auth.Vault.Type> = []
  for (const vault of requested) {
    if (vault.id) {
      resolved.push(vault)
      continue
    }
    const created = yield* admin(
      Auth.Vault,
      ["vault", "create", vault.name, "--format", "json"],
      account,
      "Vault creation is unverified; inspect your vaults before retrying",
    )
    if (created.name !== vault.name)
      return yield* fail("The created vault name did not match; inspect your vaults before retrying")
    resolved.push(created)
  }
  if (
    resolved.some((vault) => builtInVaults.includes(vault.name.toLowerCase()) || vault.id === backup.id) ||
    new Set(resolved.map((vault) => vault.id)).size !== resolved.length
  ) {
    return yield* fail("Use a dedicated automation vault and a separate backup vault for its service-account token")
  }

  const grants = resolved.flatMap((vault) => [
    "--vault",
    `${vault.id}:read_items${options.write ? ",write_items" : ""}`,
  ])
  const uncertain =
    "Service-account creation is unverified. Do not retry setup; inspect service accounts in 1Password (details suppressed)"
  const token = yield* Op.op(
    [
      "service-account",
      "create",
      name,
      ...grants,
      "--raw",
      ...(options.expiresIn ? ["--expires-in", options.expiresIn] : []),
    ],
    { account, failure: uncertain },
  ).pipe(
    Auth.asDesktop,
    Effect.flatMap(parseToken),
    Effect.mapError(() => fail(uncertain)),
  )
  yield* Auth.saveToken(token)
  const settings: Auth.Settings = { name, vaults: resolved }
  yield* Auth.saveSettings(settings)

  const visible = yield* Auth.visibleVaults(token).pipe(
    Effect.mapError(() =>
      fail(
        "The created account could not list its vaults. Its token is saved locally; inspect service-account status, do not repeat setup",
      ),
    ),
  )
  const expectedIds = resolved.map((vault) => vault.id).toSorted()
  const visibleIds = visible.map((vault) => vault.id).toSorted()
  if (visibleIds.length !== expectedIds.length || visibleIds.some((id, index) => id !== expectedIds[index])) {
    return yield* fail(
      "The created account's vault access did not match. Its token is saved locally; inspect service-account status, do not repeat setup",
    )
  }
  const saved = yield* Create.storeApiCredential({ title, vault: backup.id, account }, token).pipe(
    Auth.asDesktop,
    Effect.mapError(() =>
      fail(
        "The account is saved locally, but its 1Password token backup is unverified. Inspect the backup title with --desktop find; do not repeat setup",
      ),
    ),
  )
  yield* Auth.saveSettings({ ...settings, tokenRef: saved.ref })
  return {
    configured: true,
    name,
    vaults: visible,
    write: options.write,
    tokenRef: saved.ref,
    storage: Auth.storage,
    verified: true,
  }
})

export const connect = Effect.fn("ServiceAccount.connect")(function* (source: Op.Source, name: string) {
  if (!name.trim()) return yield* fail("A non-empty account name is required")
  yield* Auth.requireEmpty
  const token = yield* Op.privateInput(source, "service-account token", "nothing was saved").pipe(
    Effect.flatMap(parseToken),
  )
  const vaults = yield* Auth.visibleVaults(token)
  yield* Auth.saveToken(token)
  yield* Auth.saveSettings({ name: name.trim(), vaults })
  return { configured: true, name: name.trim(), vaults, storage: Auth.storage, verified: true }
})

export const status = Effect.gen(function* () {
  const saved = yield* Auth.settings
  if (!saved) return { configured: false, manageUrl }
  const vaults = yield* Auth.visibleVaults(yield* Auth.keychainToken)
  return {
    configured: true,
    name: saved.name,
    vaults,
    tokenRef: saved.tokenRef,
    storage: Auth.storage,
    verified: true,
    manageUrl,
  }
})

export const recover = Effect.fn("ServiceAccount.recover")(function* (name: string) {
  if (!name.trim()) return yield* fail("A non-empty account name is required")
  const saved = yield* Auth.settings
  const vaults = yield* Auth.visibleVaults(yield* Auth.keychainToken)
  yield* Auth.saveSettings({
    name: saved?.name ?? name.trim(),
    vaults,
    ...(saved?.tokenRef ? { tokenRef: saved.tokenRef } : {}),
  })
  return { configured: true, vaults, storage: Auth.storage, verified: true }
})

export const forget = Auth.forget

export * as ServiceAccount from "./service-account.js"
