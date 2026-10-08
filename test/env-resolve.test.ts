import { assert, describe, it } from "@effect/vitest"
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { sandbox } from "./sandbox.js"

// Records the references it was asked for, then runs the child with fictional values.
const op = `#!/bin/sh
printf '%s\\n' "$1" >> "$HOME/op.log"
[ "$1" = "run" ] || exit 71
printf '%s\\n%s\\n' "$TWO_PASSWORD_SECRET_0" "$TWO_PASSWORD_SECRET_1" > "$HOME/references"
while [ "$1" != "--" ]; do shift; done
shift
TWO_PASSWORD_SECRET_0='first "secret"' TWO_PASSWORD_SECRET_1='second
secret' exec "$@"
`

describe("env resolve", () => {
  it("resolves all unique references in one 1Password invocation", async () => {
    const box = await sandbox({ op })
    try {
      const template = join(box.home, ".env.tpl")
      const output = join(box.home, ".env")
      await writeFile(
        template,
        [
          "# Development",
          "FIRST=op://Personal/First/credential",
          "SECOND=op://Work/Second/password",
          "FIRST_AGAIN=op://Personal/First/credential",
          "",
        ].join("\n"),
      )

      const { stdout, stderr } = await box.run(["env", "resolve", template, "--output", output])
      assert.strictEqual(
        (await readdir(box.home)).some((entry) => entry.startsWith("..env.")),
        false,
      )
      assert.strictEqual(stdout, "")
      assert.match(stderr, /Resolved 3 secret references/)
      assert.deepStrictEqual((await readFile(join(box.home, "op.log"), "utf8")).trim().split("\n"), ["run"])
      assert.deepStrictEqual((await readFile(join(box.home, "references"), "utf8")).trim().split("\n"), [
        "op://Personal/First/credential",
        "op://Work/Second/password",
      ])
      assert.strictEqual(
        await readFile(output, "utf8"),
        [
          "# Development",
          'FIRST="first \\"secret\\""',
          'SECOND="second\\nsecret"',
          'FIRST_AGAIN="first \\"secret\\""',
          "",
        ].join("\n"),
      )
    } finally {
      await box.close()
    }
  })

  it("removes the temporary directory when replacing the target fails", async () => {
    const box = await sandbox({ op })
    try {
      const template = join(box.home, ".env.tpl")
      const output = join(box.home, ".env")
      await writeFile(template, "FIRST=op://Personal/First/credential\n")
      await mkdir(output)

      const result = await box.run(["env", "resolve", template, "--output", output])

      assert.notStrictEqual(result.code, 0)
      assert.strictEqual(
        (await readdir(box.home)).some((entry) => entry.startsWith("..env.")),
        false,
      )
    } finally {
      await box.close()
    }
  })
})
