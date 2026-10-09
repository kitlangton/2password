import { assert, describe, it } from "@effect/vitest"
import { mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { bun, fixture as fakeFrom, sandbox } from "./sandbox.js"

const token = "ops_fictional_service_account_sentinel"
const setupArgs = [
  "service-account",
  "setup",
  "--name",
  "Test Automation",
  "--vault",
  "Automation",
  "--save-vault",
  "Personal",
]
const fake = fakeFrom(join(import.meta.dirname, "fixtures/service-account-process.ts"))

interface Call {
  readonly command: string
  readonly args?: Array<string>
  readonly serviceAuth?: boolean
  readonly suppliedAuth?: boolean
  readonly connect?: boolean
}

const fixture = async () => {
  const box = await sandbox({ op: fake, osascript: fake, pbpaste: fake })
  const directory = box.home
  const settingsFile = join(directory, ".config/2password/service-account.json")
  const settings = async () => JSON.parse(await readFile(settingsFile, "utf8"))
  const run = async (
    args: ReadonlyArray<string>,
    scenario = "success",
    extraEnv: Record<string, string> = {},
    input = `${token}\n`,
  ) => {
    const result = await box.run(args, { input, env: { TEST_SCENARIO: scenario, ...extraEnv } })
    const calls = await box.calls<Call>()
    const observable = `${result.stdout}\n${result.stderr}\n${JSON.stringify(calls)}`
    assert.notInclude(observable, token)
    assert.notInclude(observable, Buffer.from(token).toString("hex"))
    assert.notInclude(observable, "ops_supplied_fictional_sentinel")
    assert.notInclude(observable, "fictional_new_api_key")
    assert.isFalse(calls.some((call) => call.args?.includes("whoami")))
    return { ...result, calls, op: calls.filter(({ command }) => command === "op") }
  }
  return { directory, settingsFile, settings, run, close: box.close }
}

describe.skipIf(process.platform !== "darwin" && process.platform !== "win32")("service-account CLI", () => {
  it("sets up, backs up, automatically authenticates, overrides with desktop, and forgets locally", async () => {
    const f = await fixture()
    try {
      const setup = await f.run([...setupArgs, "--write", "--account", "example.1password.com"], "success", {
        OP_SERVICE_ACCOUNT_TOKEN: "ops_supplied_fictional_sentinel",
        OP_CONNECT_TOKEN: "old-connect",
        OP_CONNECT_HOST: "https://example.invalid",
      })
      assert.strictEqual(setup.code, 0, setup.stderr)
      assert.strictEqual(
        JSON.parse(setup.stdout).storage,
        process.platform === "win32" ? "windows-dpapi" : "macos-keychain",
      )
      const receipt = JSON.parse(setup.stdout)
      assert.strictEqual(receipt.verified, true)
      assert.strictEqual(receipt.tokenRef, `op://${"p".repeat(26)}/${"i".repeat(26)}/credential`)
      assert.strictEqual((await f.settings()).tokenRef, receipt.tokenRef)
      assert.notInclude(await readFile(f.settingsFile, "utf8"), token)
      const creation = setup.op.filter(({ args }) => args?.[0] === "service-account")
      assert.strictEqual(creation.length, 1)
      assert.include(creation[0]?.args ?? [], `${"a".repeat(26)}:read_items,write_items`)
      const find = await f.run(["find", "example"])
      assert.strictEqual(find.code, 0, find.stderr)
      assert.isTrue(find.op[0]?.serviceAuth)
      const add = await f.run(
        ["create", "api-credential", "--title", "Example API Key", "--vault", "Automation", "--stdin"],
        "success",
        {},
        "fictional_new_api_key\n",
      )
      assert.strictEqual(add.code, 0, add.stderr)
      assert.strictEqual(JSON.parse(add.stdout).verified, true)
      assert.isTrue(add.op.every(({ serviceAuth }) => serviceAuth))
      const status = await f.run(["service-account", "status"])
      assert.strictEqual(JSON.parse(status.stdout).verified, true)
      const desktop = await f.run(["--desktop", "find", "example"], "success", {
        OP_SERVICE_ACCOUNT_TOKEN: "ops_supplied_fictional_sentinel",
      })
      assert.strictEqual(desktop.code, 0, desktop.stderr)
      assert.isFalse(desktop.op[0]?.serviceAuth)
      assert.isFalse(desktop.op[0]?.suppliedAuth)
      assert.isFalse(desktop.calls.some(({ command }) => command === "osascript"))
      const duplicate = await f.run(setupArgs)
      assert.notStrictEqual(duplicate.code, 0)
      assert.strictEqual(duplicate.op.length, 0)
      const forget = await f.run(["service-account", "forget"])
      assert.deepStrictEqual(JSON.parse(forget.stdout), { forgotten: true, remoteRevoked: false })
      assert.strictEqual(forget.op.length, 0)
      const after = await f.run(["find", "example"])
      assert.strictEqual(after.code, 0)
      assert.isFalse(after.op[0]?.serviceAuth)
    } finally {
      await f.close()
    }
  })

  it("can create a dedicated vault and defaults to read-only access", async () => {
    const f = await fixture()
    try {
      const result = await f.run([...setupArgs, "--create-vault", "--expires-in", "90d"], "new-vault")
      assert.strictEqual(result.code, 0, result.stderr)
      assert.deepStrictEqual(
        result.op.filter(({ args }) => args?.[1] === "create").map(({ args }) => args?.slice(0, 2)),
        [
          ["vault", "create"],
          ["service-account", "create"],
          ["item", "create"],
        ],
      )
      assert.include(
        result.op.find(({ args }) => args?.[0] === "service-account")?.args ?? [],
        `${"a".repeat(26)}:read_items`,
      )
    } finally {
      await f.close()
    }
  })

  it("keeps Automation as the default vault", async () => {
    const f = await fixture()
    try {
      const result = await f.run([...setupArgs.slice(0, 4), ...setupArgs.slice(6)])
      assert.strictEqual(result.code, 0, result.stderr)
      assert.include(
        result.op.find(({ args }) => args?.[0] === "service-account")?.args ?? [],
        `${"a".repeat(26)}:read_items`,
      )
    } finally {
      await f.close()
    }
  })

  it("grants and verifies access to multiple vaults", async () => {
    const f = await fixture()
    try {
      const result = await f.run(
        [
          ...setupArgs.slice(0, 4),
          "--vault",
          "github-actions",
          "--vault",
          "Automation",
          ...setupArgs.slice(6),
          "--write",
        ],
        "multi-vault",
      )
      assert.strictEqual(result.code, 0, result.stderr)
      const creation = result.op.find(({ args }) => args?.[0] === "service-account")?.args ?? []
      assert.include(creation, `${"a".repeat(26)}:read_items,write_items`)
      assert.include(creation, `${"g".repeat(26)}:read_items,write_items`)
      assert.deepStrictEqual(
        JSON.parse(result.stdout)
          .vaults.map(({ name }: { name: string }) => name)
          .toSorted(),
        ["Automation", "github-actions"],
      )
    } finally {
      await f.close()
    }
  })

  it("refuses a multi-vault setup when the token grants do not match", async () => {
    const f = await fixture()
    try {
      const result = await f.run(
        [...setupArgs.slice(0, 4), "--vault", "github-actions", "--vault", "Automation", ...setupArgs.slice(6)],
        "wrong-grants",
      )
      assert.notStrictEqual(result.code, 0)
      assert.include(result.stderr, "vault access did not match")
      assert.strictEqual(result.op.filter(({ args }) => args?.[0] === "service-account").length, 1)
    } finally {
      await f.close()
    }
  })

  for (const scenario of ["keychain-denied", "duplicate-backup", "new-vault"]) {
    it(`does not create an account after ${scenario}`, async () => {
      const f = await fixture()
      try {
        const result = await f.run(setupArgs, scenario)
        assert.notStrictEqual(result.code, 0)
        assert.isFalse(result.op.some(({ args }) => args?.[0] === "service-account"))
      } finally {
        await f.close()
      }
    })
  }

  for (const scenario of ["create-failure", "keychain-write-failure", "wrong-grants", "backup-failure"]) {
    it(`reports partial setup without retrying or exposing credentials on ${scenario}`, async () => {
      const f = await fixture()
      try {
        const result = await f.run([...setupArgs, "--log-level", "debug"], scenario)
        assert.notStrictEqual(result.code, 0)
        assert.strictEqual(result.stdout, "")
        assert.strictEqual(result.op.filter(({ args }) => args?.[0] === "service-account").length, 1)
        if (scenario === "backup-failure") {
          assert.include(result.stderr, "saved locally")
          assert.isUndefined((await f.settings()).tokenRef)
          const status = await f.run(["service-account", "status"])
          assert.strictEqual(JSON.parse(status.stdout).verified, true)
        }
      } finally {
        await f.close()
      }
    })
  }

  it("imports a token, fails closed on lost Keychain access, and supports explicit environment auth", async () => {
    const f = await fixture()
    try {
      const connected = await f.run(["service-account", "connect", "--stdin"])
      assert.strictEqual(connected.code, 0, connected.stderr)
      const failed = await f.run(["find", "example"], "keychain-denied")
      assert.notStrictEqual(failed.code, 0)
      assert.strictEqual(failed.op.length, 0)
      const override = await f.run(["find", "example"], "keychain-denied", {
        OP_SERVICE_ACCOUNT_TOKEN: "ops_supplied_fictional_sentinel",
        OP_CONNECT_HOST: "https://example.invalid",
        OP_CONNECT_TOKEN: "ignored",
      })
      assert.strictEqual(override.code, 0, override.stderr)
      assert.isTrue(override.op[0]?.suppliedAuth)
      assert.isFalse(override.op[0]?.connect)
      const failure = await f.run(["find", "example"], "op-failure")
      assert.notStrictEqual(failure.code, 0)
      assert.include(failure.stderr, "details suppressed")
      const run = await f.run([
        "run",
        "--env",
        "EXAMPLE=op://Automation/Example/credential",
        "--",
        "example-cli",
        "--desktop",
      ])
      assert.strictEqual(run.code, 7)
      // Windows has no `env -u`; a Bun helper removes the token there.
      const withoutToken =
        process.platform === "win32"
          ? [bun, join(import.meta.dirname, "..", "src", "without-token.ts")]
          : ["env", "-u", "OP_SERVICE_ACCOUNT_TOKEN"]
      assert.deepStrictEqual(run.op[0]?.args, ["run", "--", ...withoutToken, "example-cli", "--desktop"])
      await rm(f.settingsFile)
      const recovered = await f.run(["service-account", "recover"])
      assert.strictEqual(recovered.code, 0, recovered.stderr)
      assert.strictEqual((await f.settings()).vaults.length, 1)
      assert.isFalse(recovered.op.some(({ args }) => args?.includes("create")))
    } finally {
      await f.close()
    }
  })

  it("does not read secrets for help, rejects invalid input, and bypasses broken settings explicitly", async () => {
    const f = await fixture()
    try {
      const help = await f.run(["service-account", "setup", "--help"])
      assert.strictEqual(help.code, 0)
      assert.deepStrictEqual(help.calls, [])
      const invalid = await f.run(["service-account", "connect", "--stdin"], "success", {}, "not-a-service-token")
      assert.notStrictEqual(invalid.code, 0)
      assert.strictEqual(invalid.op.length, 0)
      const rejected = await f.run(["service-account", "connect", "--clipboard"], "token-rejected")
      assert.notStrictEqual(rejected.code, 0)
      assert.isFalse(rejected.calls.some(({ args }) => args?.[3] === "add"))
      await mkdir(join(f.directory, ".config/2password"), { recursive: true })
      await writeFile(f.settingsFile, "broken")
      const normal = await f.run(["find", "example"])
      assert.notStrictEqual(normal.code, 0)
      assert.strictEqual(normal.op.length, 0)
      const desktop = await f.run(["find", "example", "--desktop"])
      assert.strictEqual(desktop.code, 0, desktop.stderr)
    } finally {
      await f.close()
    }
  })
})
