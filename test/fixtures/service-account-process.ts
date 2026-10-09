import { normalize } from "./platform.js"
import { appendFileSync, existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs"
import { join } from "node:path"

// Fictional sentinels only. Fixtures receive no live credentials or live op path.
const token = "ops_fictional_service_account_sentinel"
const home = process.env.HOME
const calls = process.env.TEST_CALLS
if (!home || !calls) throw new Error("Fixture environment missing")
const keychain = join(home, "keychain-fixture")
const automationId = "a".repeat(26)
const githubActionsId = "g".repeat(26)
const personalId = "p".repeat(26)
const itemId = "i".repeat(26)
const automation = { id: automationId, name: "Automation" }
const githubActions = { id: githubActionsId, name: "github-actions" }
const personal = { id: personalId, name: "Personal" }
const scenario = process.env.TEST_SCENARIO
const [command, ...args] = normalize(process.argv.slice(2))
const option = (flag: string) => args[args.indexOf(flag) + 1]
const record = (event: unknown) => appendFileSync(calls, `${JSON.stringify(event)}\n`)
record({
  command,
  args,
  serviceAuth: process.env.OP_SERVICE_ACCOUNT_TOKEN === token,
  suppliedAuth: process.env.OP_SERVICE_ACCOUNT_TOKEN === "ops_supplied_fictional_sentinel",
  connect: !!process.env.OP_CONNECT_TOKEN,
  account: process.env.OP_ACCOUNT,
})
const fail = () => {
  console.log(token)
  console.error(`Private helper diagnostics ${token}`)
  process.exit(1)
}

if (command === "osascript") {
  const operation = args[3]
  if (operation === "exists" || operation === "get") {
    if (scenario === "keychain-denied") fail()
    if (!existsSync(keychain)) {
      if (operation === "get") fail()
      console.log("missing")
      process.exit(0)
    }
    console.log(operation === "get" ? readFileSync(keychain, "utf8") : "found")
    process.exit(0)
  }
  if (operation === "add") {
    const input = await Bun.stdin.text()
    if (input !== token || existsSync(keychain)) fail()
    record({ command: "private-keychain-input-verified" })
    if (scenario !== "keychain-write-failure") writeFileSync(keychain, token)
    // Successful process exit alone must never count as storage verification.
    process.exit(0)
  }
  if (operation === "remove") {
    if (existsSync(keychain)) unlinkSync(keychain)
    process.exit(0)
  }
  fail()
}
if (command === "pbpaste") {
  console.log(token)
  process.exit(0)
}
if (command !== "op") fail()
if (args[0] === "service-account" && args[1] === "create") {
  if (scenario === "create-failure") fail()
  if (process.env.OP_SERVICE_ACCOUNT_TOKEN || process.env.OP_CONNECT_TOKEN || !args.includes("--raw")) fail()
  console.log(token)
  process.exit(0)
}
if (args[0] === "vault" && args[1] === "list") {
  if (process.env.OP_SERVICE_ACCOUNT_TOKEN) {
    if (scenario === "token-rejected") fail()
    if (process.env.OP_CONNECT_TOKEN || process.env.OP_ACCOUNT) fail()
    console.log(
      JSON.stringify(
        scenario === "wrong-grants"
          ? [automation, personal]
          : scenario === "multi-vault"
            ? [automation, githubActions]
            : [automation],
      ),
    )
  } else
    console.log(
      JSON.stringify(
        scenario === "new-vault"
          ? [personal]
          : scenario === "multi-vault" || scenario === "wrong-grants"
            ? [automation, githubActions, personal]
            : [automation, personal],
      ),
    )
  process.exit(0)
}
if (args[0] === "vault" && args[1] === "create") {
  console.log(JSON.stringify(automation))
  process.exit(0)
}
if (args[0] === "item" && args[1] === "list") {
  if (scenario === "op-failure") fail()
  console.log(
    JSON.stringify(
      scenario === "duplicate-backup" ? [{ title: "1Password Test Automation Service Account Token" }] : [],
    ),
  )
  process.exit(0)
}
if (args[0] === "item" && args[1] === "create") {
  if (scenario === "backup-failure") fail()
  const item = JSON.parse(await Bun.stdin.text())
  const serviceWrite = option("--vault") === "Automation"
  if (item.category !== "API_CREDENTIAL") fail()
  if (serviceWrite) {
    if (item.fields[0].value !== "fictional_new_api_key" || process.env.OP_SERVICE_ACCOUNT_TOKEN !== token) fail()
  } else if (item.fields[0].value !== token || option("--vault") !== personalId || process.env.OP_SERVICE_ACCOUNT_TOKEN)
    fail()
  record({ command: "private-backup-input-verified" })
  const receipt = { ...item, id: itemId, vault: serviceWrite ? automation : personal }
  writeFileSync(join(home, "backup-fixture"), JSON.stringify(receipt))
  console.log(JSON.stringify(receipt))
  process.exit(0)
}
if (args[0] === "item" && args[1] === "get") {
  console.log(readFileSync(join(home, "backup-fixture"), "utf8"))
  process.exit(0)
}
if (args[0] === "run") {
  console.log("Child output")
  process.exit(7)
}
fail()
