import { Console, Effect, FileSystem, Path } from "effect"
import { Op } from "./op.js"

export interface Assignment {
  readonly name: string
  readonly reference: string
}

type EnvLine =
  | { readonly _tag: "Literal"; readonly value: string }
  | { readonly _tag: "Reference"; readonly name: string; readonly reference: string }

const namePattern = /^[A-Za-z_][A-Za-z0-9_]*$/

export const parseAssignment = (assignment: string): Assignment => {
  const equals = assignment.indexOf("=")
  if (equals < 1) throw new Error(`Expected NAME=op://reference, received: ${assignment}`)
  const name = assignment.slice(0, equals)
  const reference = assignment.slice(equals + 1)
  if (!namePattern.test(name)) throw new Error(`Invalid environment variable name: ${name}`)
  if (!reference.startsWith("op://")) throw new Error(`Secret reference must start with op://: ${name}`)
  return { name, reference }
}

const unquote = (value: string): string =>
  value.length >= 2 &&
  ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
    ? value.slice(1, -1)
    : value

const parseEnv = (content: string): ReadonlyArray<EnvLine> =>
  content.split(/\r?\n/).map((original) => {
    const trimmed = original.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return { _tag: "Literal", value: original }
    const assignment = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed
    const equals = assignment.indexOf("=")
    if (equals < 1) return { _tag: "Literal", value: original }
    const name = assignment.slice(0, equals).trim()
    const reference = unquote(assignment.slice(equals + 1).trim())
    if (!namePattern.test(name) || !reference.startsWith("op://")) return { _tag: "Literal", value: original }
    return { _tag: "Reference", name, reference }
  })

export const renderEnv = (assignments: ReadonlyArray<Assignment>): string =>
  assignments.map(({ name, reference }) => `${name}=${reference}`).join("\n") + "\n"

const quoteEnvValue = (value: string): string =>
  `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n").replaceAll("\r", "\\r")}"`

// `resolve` must return one value per reference, in order.
export const resolveEnv = <E, R>(
  content: string,
  resolve: (references: ReadonlyArray<string>) => Effect.Effect<ReadonlyArray<string>, E, R>,
): Effect.Effect<{ readonly content: string; readonly count: number }, E, R> =>
  Effect.gen(function* () {
    const parsed = parseEnv(content)
    const references = [...new Set(parsed.flatMap((line) => (line._tag === "Reference" ? [line.reference] : [])))]
    const resolved = yield* resolve(references)
    if (resolved.length !== references.length)
      throw new Error("Secret resolver returned an unexpected number of values")
    const values = new Map(references.map((reference, index) => [reference, resolved[index]!]))
    return {
      content: parsed
        .map((line) =>
          line._tag === "Literal"
            ? line.value
            : `${line.name}=${quoteEnvValue(values.get(line.reference)!.replace(/\n$/, ""))}`,
        )
        .join("\n"),
      count: parsed.filter((line) => line._tag === "Reference").length,
    }
  })

export const read = (reference: string) => Op.op(["read", reference], {})

// Resolves every reference with a single `op run`, so one authorization covers the whole file.
export const readMany = Effect.fn("Env.readMany")(function* (references: ReadonlyArray<string>) {
  if (references.length === 0) return []
  const output = yield* Op.op(
    [
      "run",
      "--no-masking",
      "--",
      process.execPath,
      "-e",
      "const count=Number(process.argv[1]);process.stdout.write(JSON.stringify(Array.from({length:count},(_,index)=>process.env[`TWO_PASSWORD_SECRET_${index}`])))",
      String(references.length),
    ],
    { env: Object.fromEntries(references.map((reference, index) => [`TWO_PASSWORD_SECRET_${index}`, reference])) },
  )
  return yield* Effect.try({
    try: () => {
      const values: unknown = JSON.parse(output)
      if (
        !Array.isArray(values) ||
        values.length !== references.length ||
        !values.every((value) => typeof value === "string")
      ) {
        throw new Error("Invalid secret batch")
      }
      return values as ReadonlyArray<string>
    },
    catch: () => Op.fail("1Password returned an invalid secret batch"),
  })
})

export const run = (assignments: ReadonlyArray<Assignment>, command: ReadonlyArray<string>) =>
  Op.exec(["run"], command, Object.fromEntries(assignments.map(({ name, reference }) => [name, reference])))

export const runFile = (file: string, command: ReadonlyArray<string>) => Op.exec(["run", `--env-file=${file}`], command)

export const write = Effect.fn("Env.write")(function* (file: string, assignments: ReadonlyArray<Assignment>) {
  yield* (yield* FileSystem.FileSystem).writeFileString(file, renderEnv(assignments))
  yield* Console.error(`Wrote ${assignments.length} secret references to ${file}`)
})

// Writes plaintext atomically with mode 0600 and warns that the result holds secrets.
export const resolveFile = Effect.fn("Env.resolveFile")(function* (file: string, target: string) {
  const fs = yield* FileSystem.FileSystem
  const path = yield* Path.Path
  const result = yield* resolveEnv(yield* fs.readFileString(file), readMany)
  const temporary = yield* fs.makeTempFile({ directory: path.dirname(target), prefix: `.${path.basename(target)}.` })
  yield* Effect.gen(function* () {
    yield* fs.chmod(temporary, 0o600)
    yield* fs.writeFileString(temporary, result.content, { mode: 0o600 })
    yield* fs.rename(temporary, target)
  }).pipe(Effect.ensuring(fs.remove(path.dirname(temporary), { force: true, recursive: true }).pipe(Effect.ignore)))
  yield* Console.error(
    `Resolved ${result.count} secret references into ${target}; this file now contains plaintext secrets`,
  )
})

export * as Env from "./env.js"
