import { BunServices } from "@effect/platform-bun"
import { Console, Effect, Option } from "effect"
import { Argument, Command, Flag } from "effect/cli"
import packageJson from "../package.json" with { type: "json" }
import { decodeTrailingArguments, normalizeTrailingArguments } from "./arguments.js"
import { Auth } from "./auth.js"
import { Create } from "./create.js"
import { Discover } from "./discover.js"
import { Doctor } from "./doctor.js"
import { Env, parseAssignment } from "./env.js"
import { Lease } from "./lease.js"
import { Op } from "./op.js"
import { Password } from "./password.js"
import { Request } from "./request.js"
import { LeasedRequest } from "./request-leased.js"
import { ServiceAccount } from "./service-account.js"

const print = (value: unknown) => Console.log(JSON.stringify(value, null, 2))
const fail = (message: string) => Effect.fail(Op.fail(message))

const toggle = (name: string) => Flag.Boolean(name).pipe(Flag.withDefault(false))
const optional = <A>(flag: Flag.Flag<A>) => flag.pipe(Flag.optional, Flag.map(Option.getOrUndefined))
const account = optional(Flag.String("account")).pipe(Flag.withDescription("1Password account"))
const vaultFilter = optional(Flag.String("vault")).pipe(Flag.withDescription("Limit results to a vault"))
const accountName = Flag.String("name").pipe(Flag.withDefault("2password Automation"))

const sourceFlags = {
  clipboard: toggle("clipboard").pipe(
    Flag.withDescription("Read the macOS or Windows clipboard without printing or clearing it"),
  ),
  stdin: toggle("stdin").pipe(Flag.withDescription("Read piped stdin, never an argument")),
}
const source = ({ clipboard, stdin }: { readonly clipboard: boolean; readonly stdin: boolean }) =>
  clipboard === stdin
    ? fail("Choose exactly one of --clipboard or --stdin")
    : Effect.succeed<Op.Source>(clipboard ? "clipboard" : "stdin")

const assignmentError = (error: unknown) => (error instanceof Error ? error.message : String(error))
const trailingCommand = Argument.String("command").pipe(Argument.atLeast(1))

// Discovery: metadata and op:// references, never values.

const find = Command.make(
  "find",
  {
    queries: Argument.String("query").pipe(
      Argument.atLeast(1),
      Argument.withDescription("One or more title queries; quote queries containing spaces"),
    ),
    account,
    vault: vaultFilter,
  },
  ({ queries, ...scope }) => Discover.find(queries, scope).pipe(Effect.flatMap(print)),
).pipe(Command.withDescription("Find secret references without revealing values"))

const inventory = Command.make("inventory", { account, vault: vaultFilter }, (scope) =>
  Discover.inventory(scope).pipe(Effect.flatMap((items) => print({ items }))),
).pipe(Command.withDescription("List audit-safe item metadata without revealing values"))

const audit = Command.make("audit", { account, vault: vaultFilter }, (scope) =>
  Discover.audit(scope).pipe(Effect.flatMap(print)),
).pipe(Command.withDescription("Report organization issues without revealing values"))

// Writes: private input in, verified receipt out.

const createApiCredential = Command.make(
  "api-credential",
  {
    title: Flag.String("title").pipe(Flag.withDescription("Non-secret item title, e.g. Example API Key")),
    vault: Flag.String("vault").pipe(
      Flag.withDescription("Destination vault name or ID; required, no implicit default"),
    ),
    account,
    ...sourceFlags,
    url: optional(Flag.String("url")).pipe(Flag.withDescription("Optional non-secret website URL")),
    notes: optional(Flag.String("notes")).pipe(Flag.withDescription("Optional non-secret operational notes")),
  },
  ({ clipboard, stdin, ...destination }) =>
    Effect.gen(function* () {
      yield* print(yield* Create.apiCredential(destination, yield* source({ clipboard, stdin })))
    }),
).pipe(Command.withDescription("Create and verify an API Credential without revealing its value"))

const create = Command.make("create").pipe(
  Command.withDescription("Create a new credential from private input"),
  Command.withSubcommands([createApiCredential]),
)

const password = Command.make(
  "password",
  {
    item: Argument.String("item"),
    vault: Flag.String("vault"),
    account,
    ...sourceFlags,
    apply: toggle("apply").pipe(Flag.withDescription("Update and verify; otherwise only compare")),
    repairImportedFields: toggle("repair-imported-fields").pipe(
      Flag.withDescription("Preserve unnamed imported fields under concealed labels; requires --apply"),
    ),
  },
  ({ clipboard, stdin, ...options }) =>
    Effect.gen(function* () {
      yield* print(yield* Password.password({ ...options, source: yield* source({ clipboard, stdin }) }))
    }),
).pipe(Command.withDescription("Compare or update a Login password from private input without revealing it"))

const doctor = Command.make("doctor", {}, () => Doctor.doctor(packageJson.version).pipe(Effect.flatMap(print))).pipe(
  Command.withDescription("Check the setup without authenticating or prompting; safe to paste into an issue"),
)

// Destination-bound consumption: plaintext stays inside this process and the HTTPS request.

const destinationRequest = Command.make(
  "request",
  {
    url: Argument.String("url").pipe(Argument.withDescription("Exact HTTPS URL; port 443 only")),
    secret: Flag.String("secret").pipe(Flag.withDescription("op:// reference injected into the request header")),
    lease: Flag.String("lease").pipe(Flag.withDescription("Approved short-lived lease ID")),
    header: Flag.String("header").pipe(
      Flag.withDefault("Authorization"),
      Flag.withDescription("Secret header: Authorization or X-API-Key"),
    ),
    prefix: Flag.String("prefix").pipe(
      Flag.withDefault("Bearer "),
      Flag.withDescription("Non-secret text prepended to the credential"),
    ),
  },
  ({ url, secret, lease, header, prefix }) =>
    LeasedRequest.request(lease, { url, reference: secret, header, prefix }).pipe(Effect.flatMap(print)),
).pipe(Command.withDescription("GET an HTTPS URL with a leased credential; response body stays private"))

const leaseApprove = Command.make(
  "approve",
  {
    url: Argument.String("url").pipe(Argument.withDescription("Exact HTTPS URL approved for this credential")),
    secret: Flag.String("secret").pipe(Flag.withDescription("op:// reference to authorize")),
    header: Flag.String("header").pipe(
      Flag.withDefault("Authorization"),
      Flag.withDescription("Secret header: Authorization or X-API-Key"),
    ),
    prefix: Flag.String("prefix").pipe(
      Flag.withDefault("Bearer "),
      Flag.withDescription("Non-secret text prepended to the credential"),
    ),
    expiresIn: Flag.String("expires-in").pipe(
      Flag.withDefault("10m"),
      Flag.withDescription("Lease lifetime; maximum 1h"),
    ),
    uses: Flag.String("uses").pipe(Flag.withDefault("1"), Flag.withDescription("Atomic use budget; maximum 10")),
  },
  ({ url, secret, header, prefix, expiresIn, uses }) =>
    Effect.gen(function* () {
      const binding = yield* Request.describe({ url, reference: secret, header, prefix })
      yield* Console.error(
        `Approve lease: ${JSON.stringify({
          capability: binding.capability,
          method: binding.method,
          reference: binding.reference,
          destination: binding.destination,
          destinationFingerprint: binding.destinationFingerprint,
          expiresIn,
          uses,
        })}`,
      )
      yield* print(yield* Lease.grant(binding, { expiresIn, uses: Number(uses) }))
    }),
).pipe(Command.withDescription("Interactively approve a short-lived request lease using desktop authentication"))

const leaseStatus = Command.make(
  "status",
  { id: Argument.String("id") },
  ({ id }) => Lease.status(id).pipe(Effect.flatMap(print)),
).pipe(Command.withDescription("Show non-secret lease state"))

const leaseRevoke = Command.make(
  "revoke",
  { id: Argument.String("id") },
  ({ id }) => Lease.revoke(id).pipe(Effect.flatMap(print)),
).pipe(Command.withDescription("Revoke a local lease immediately"))

const lease = Command.make("lease").pipe(
  Command.withDescription("Approve, inspect, and revoke short-lived credential-use leases"),
  Command.withSubcommands([leaseApprove, leaseStatus, leaseRevoke]),
)

// Consumption: values go to a process or file, not to the conversation.

const read = Command.make("read", { reference: Argument.String("reference") }, ({ reference }) =>
  Env.read(reference).pipe(Effect.flatMap((value) => Effect.sync(() => process.stdout.write(value)))),
).pipe(Command.withDescription("Explicitly write one secret value to stdout"))

const run = Command.make(
  "run",
  {
    env: Flag.String("env").pipe(
      Flag.mapTryCatch(parseAssignment, assignmentError),
      Flag.atLeast(1),
      Flag.withDescription("NAME=op://reference; repeat for each secret"),
    ),
    command: trailingCommand,
  },
  ({ env, command }) =>
    Env.run(env, decodeTrailingArguments(command)).pipe(
      Effect.map((code) => {
        process.exitCode = code
      }),
    ),
).pipe(Command.withDescription("Run a command with secret references injected"))

const envWrite = Command.make(
  "write",
  {
    file: Argument.String("file"),
    assignments: Argument.String("assignment").pipe(
      Argument.mapTryCatch(parseAssignment, assignmentError),
      Argument.atLeast(1),
    ),
  },
  ({ file, assignments }) => Env.write(file, assignments),
).pipe(Command.withDescription("Replace an env file with secret references"))

const envResolve = Command.make(
  "resolve",
  {
    file: Argument.String("file"),
    output: optional(Flag.String("output")),
    inPlace: toggle("in-place"),
  },
  ({ file, output, inPlace }) =>
    inPlace === (output !== undefined)
      ? fail("Choose exactly one of --output or --in-place")
      : Env.resolveFile(file, output ?? file),
).pipe(Command.withDescription("Materialize secret references into a plaintext env file"))

const envRun = Command.make("run", { file: Argument.String("file"), command: trailingCommand }, ({ file, command }) =>
  Env.runFile(file, decodeTrailingArguments(command)).pipe(
    Effect.map((code) => {
      process.exitCode = code
    }),
  ),
).pipe(Command.withDescription("Run a command from a reference-based env file"))

const env = Command.make("env").pipe(
  Command.withDescription("Create, resolve, and use env files"),
  Command.withSubcommands([envWrite, envResolve, envRun]),
)

// Unattended access: a dedicated service account remembered in macOS Keychain or, on Windows, a DPAPI-encrypted file.

const serviceSetup = Command.make(
  "setup",
  {
    name: accountName,
    vault: Flag.String("vault").pipe(Flag.withDefault("Automation")),
    saveVault: Flag.String("save-vault").pipe(
      Flag.withDescription("Existing administrator vault for the token backup, e.g. Personal"),
    ),
    account,
    createVault: toggle("create-vault").pipe(Flag.withDescription("Create the automation vault if it does not exist")),
    write: toggle("write").pipe(Flag.withDescription("Allow adding and updating items in the automation vault")),
    expiresIn: optional(Flag.String("expires-in")).pipe(
      Flag.withDescription("Optional service-account lifetime, e.g. 90d"),
    ),
  },
  (options) => ServiceAccount.setup(options).pipe(Effect.flatMap(print)),
).pipe(
  Command.withDescription(
    "Create an account, back up its token, and remember it in macOS Keychain (DPAPI on Windows) using desktop authentication",
  ),
)

const serviceConnect = Command.make("connect", { name: accountName, ...sourceFlags }, ({ name, ...flags }) =>
  Effect.gen(function* () {
    yield* print(yield* ServiceAccount.connect(yield* source(flags), name))
  }),
).pipe(Command.withDescription("Verify and remember an existing service-account token without printing it"))

const serviceStatus = Command.make("status", {}, () => ServiceAccount.status.pipe(Effect.flatMap(print))).pipe(
  Command.withDescription("Verify the saved account and list the vaults it can access"),
)

const serviceRecover = Command.make("recover", { name: accountName }, ({ name }) =>
  ServiceAccount.recover(name).pipe(Effect.flatMap(print)),
).pipe(Command.withDescription("Restore local settings from an existing Keychain token without creating an account"))

const serviceForget = Command.make("forget", {}, () => ServiceAccount.forget.pipe(Effect.flatMap(print))).pipe(
  Command.withDescription("Remove this Mac's saved token; does not revoke the remote service account"),
)

const serviceAccount = Command.make("service-account").pipe(
  Command.withDescription("Set up and manage unattended 1Password access on this Mac"),
  Command.withSubcommands([serviceSetup, serviceConnect, serviceStatus, serviceRecover, serviceForget]),
)

const root = Command.make("2password").pipe(
  Command.withDescription("Find, create, and use secrets without exposing them by default"),
  Command.withSharedFlags({
    desktop: toggle("desktop").pipe(
      Flag.withDescription("Use desktop authentication instead of the saved or environment service account"),
    ),
  }),
  Command.withSubcommands([
    find,
    inventory,
    audit,
    create,
    password,
    lease,
    destinationRequest,
    read,
    run,
    env,
    serviceAccount,
    doctor,
  ]),
  Command.provideEffect(Op.Credentials, ({ desktop }) => Auth.make(desktop)),
)

export const program = Command.runWith(root, { version: packageJson.version })(
  normalizeTrailingArguments(process.argv.slice(2)),
).pipe(
  Effect.provide(BunServices.layer),
  Effect.catchTag("Failure", (error) =>
    Console.error(`2password: ${error.message}`).pipe(
      Effect.andThen(
        Effect.sync(() => {
          process.exitCode = 1
        }),
      ),
    ),
  ),
)
