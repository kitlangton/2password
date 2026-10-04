import { Config, Effect, FileSystem, Option, Path, Redacted, Schema, Stream } from "effect"
import { ChildProcess, ChildProcessSpawner } from "effect/process"
import { fileURLToPath } from "node:url"
import { Op } from "./op.js"

const { fail } = Op

export const Vault = Schema.Struct({ id: Op.Id, name: Schema.String })
export const Settings = Schema.Struct({
  name: Schema.String,
  vaults: Schema.Array(Vault),
  tokenRef: Schema.optionalKey(
    Schema.String.check(Schema.isPattern(/^op:\/\/[a-z0-9]{26}\/[a-z0-9]{26}\/credential$/)),
  ),
})
export interface Settings extends Schema.Schema.Type<typeof Settings> {}

export const desktopEnvironment: Op.Environment = {
  OP_SERVICE_ACCOUNT_TOKEN: undefined,
  OP_CONNECT_HOST: undefined,
  OP_CONNECT_TOKEN: undefined,
}

export const serviceEnvironment = (token: Redacted.Redacted<string>): Op.Environment => ({
  OP_SERVICE_ACCOUNT_TOKEN: Redacted.value(token),
  OP_ACCOUNT: undefined,
  OP_CONNECT_HOST: undefined,
  OP_CONNECT_TOKEN: undefined,
})

export const asDesktop = Op.withCredentials(desktopEnvironment)

// Priority: --desktop, then OP_SERVICE_ACCOUNT_TOKEN, then the saved Keychain account,
// then op's own authentication. A broken saved account fails instead of widening access.
export const make = Effect.fn("Auth.make")(function* (desktop: boolean) {
  const context = yield* Effect.context<FileSystem.FileSystem | Path.Path | ChildProcessSpawner.ChildProcessSpawner>()
  const environment = yield* Effect.cached(
    Effect.gen(function* () {
      if (desktop) return desktopEnvironment
      const supplied = yield* Config.option(Config.Redacted("OP_SERVICE_ACCOUNT_TOKEN"))
      if (Option.isSome(supplied)) return serviceEnvironment(supplied.value)
      if (!(yield* settings)) return {}
      return serviceEnvironment(yield* keychainToken)
    }).pipe(
      Effect.mapError((error) =>
        error instanceof Op.Failure ? error : fail("Could not resolve service-account authentication"),
      ),
    ),
  )
  return Op.Credentials.of({ environment: environment.pipe(Effect.provideContext(context)) })
})

// One fixed Keychain identity holds the token, via the native Security API (keychain.jxa.js).
// The token crosses only stdin; it never reaches argv, the settings file, or diagnostics.
// On Windows the same four operations run against a DPAPI-encrypted file (credential.win.ps1).
const keychain = (
  operation: "get" | "exists" | "add" | "remove",
  message: string,
  token?: Redacted.Redacted<string>,
) => {
  const identity = [operation, "dev.kitlangton.2password", "service-account"]
  const options = {
    stdin: token === undefined ? ("ignore" as const) : Stream.make(new TextEncoder().encode(Redacted.value(token))),
    stderr: "ignore" as const,
  }
  return Op.capture(
    Op.windows
      ? ChildProcess.make(
          Op.program("powershell"),
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            fileURLToPath(new URL("./credential.win.ps1", import.meta.url)),
            ...identity,
          ],
          options,
        )
      : ChildProcess.make(
          "osascript",
          ["-l", "JavaScript", fileURLToPath(new URL("./keychain.jxa.js", import.meta.url)), ...identity],
          options,
        ),
    message,
  )
}

// Reported by service-account commands so callers can tell where the token lives.
export const storage = Op.windows ? "windows-dpapi" : "macos-keychain"

const requireMacOS = (message: string) =>
  process.platform === "darwin" || Op.windows ? Effect.void : Effect.fail(fail(message))

export const keychainToken = requireMacOS(
  "Saved service accounts require macOS Keychain; use OP_SERVICE_ACCOUNT_TOKEN on other platforms",
).pipe(
  Effect.andThen(
    keychain(
      "get",
      "Could not read the saved service-account token; check local credential storage or use --desktop. Desktop authentication was not attempted",
    ),
  ),
  Effect.map((token) => Redacted.make(token.replace(/\r?\n$/, ""))),
)

export const saveToken = Effect.fn("Auth.saveToken")(function* (token: Redacted.Redacted<string>) {
  yield* requireMacOS("Saving a service account requires macOS Keychain")
  yield* keychain("add", "Local credential storage failed; account creation must not be retried", token)
  if (Redacted.value(yield* keychainToken) !== Redacted.value(token)) {
    return yield* fail("Local credential read-back did not match; account creation must not be retried")
  }
})

const settingsPath = Effect.gen(function* () {
  // PowerShell and cmd usually have no HOME on Windows; fall back to USERPROFILE.
  const home = yield* Config.String("HOME").pipe(Config.orElse(() => Config.String("USERPROFILE")))
  return (yield* Path.Path).join(home, ".config", "2password", "service-account.json")
}).pipe(Effect.mapError(() => fail("Could not locate the 2password settings directory")))

export const settings = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem
  const file = yield* settingsPath
  if (!(yield* fs.exists(file))) return undefined
  return yield* fs
    .readFileString(file)
    .pipe(Effect.flatMap(Schema.decodeUnknownEffect(Schema.fromJsonString(Settings))))
}).pipe(Effect.mapError(() => fail("Could not read service-account settings; use --desktop for administrative access")))

export const saveSettings = Effect.fn("Auth.saveSettings")(
  function* (value: Settings) {
    const fs = yield* FileSystem.FileSystem
    const path = yield* Path.Path
    const file = yield* settingsPath
    yield* fs.makeDirectory(path.dirname(file), { recursive: true, mode: 0o700 })
    const temporary = yield* fs.makeTempFile({ directory: path.dirname(file), prefix: ".service-account." })
    yield* fs
      .writeFileString(temporary, `${JSON.stringify(value, null, 2)}\n`)
      .pipe(
        Effect.andThen(fs.rename(temporary, file)),
        Effect.ensuring(fs.remove(temporary, { force: true }).pipe(Effect.ignore)),
      )
  },
  Effect.mapError(() =>
    fail(
      "The token may be saved locally, but local settings could not be saved; use service-account recover, do not repeat account creation",
    ),
  ),
)

export const requireEmpty = Effect.gen(function* () {
  yield* requireMacOS("Service-account setup requires macOS Keychain")
  if (yield* settings)
    return yield* fail(
      "A service account is already configured; inspect it with service-account status before using service-account forget",
    )
  const result = (yield* keychain("exists", "Could not check local credential storage; nothing was created")).trim()
  if (result === "found")
    return yield* fail(
      "A service-account token already exists in local credential storage; use service-account recover or forget before setup",
    )
  if (result !== "missing") return yield* fail("Could not check local credential storage; nothing was created")
})

export const forget = Effect.gen(function* () {
  yield* requireMacOS("Local service-account storage requires macOS Keychain")
  yield* keychain("remove", "Could not remove the saved service-account token")
  const remaining = (yield* keychain("exists", "Could not verify removal of the saved service-account token")).trim()
  if (remaining !== "missing") return yield* fail("Could not verify removal of the local Keychain token")
  yield* (yield* FileSystem.FileSystem).remove(yield* settingsPath, { force: true })
  return { forgotten: true, remoteRevoked: false }
}).pipe(Effect.mapError(() => fail("Local removal is unverified; remote service-account access has not been revoked")))

export const visibleVaults = Effect.fn("Auth.visibleVaults")(function* (token: Redacted.Redacted<string>) {
  const vaults = yield* Op.json(Schema.Array(Vault), ["vault", "list", "--format", "json"], {
    failure: "The service-account token could not list its vaults (1Password details suppressed)",
  }).pipe(Op.withCredentials(serviceEnvironment(token)))
  return vaults.map(({ id, name }) => ({ id, name }))
})

export * as Auth from "./auth.js"
