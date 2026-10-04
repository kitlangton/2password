import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { Op } from "../src/op.js"
import { Request, isPublicAddress } from "../src/request.js"\nimport { sandbox } from "./sandbox.js"

const secret = "fictional-request-secret"

describe("request", () => {
  it.effect("binds the secret to a validated public destination and redacts exact echoes", () =>
    Effect.gen(function* () {
      const result = yield* Request.requestWith(
        {
          url: "https://api.example.com/v1/me?view=full",
          reference: "op://Personal/Example/credential",
          header: "Authorization",
          prefix: "Bearer ",
        },
        {
          resolve: () => Effect.succeed(`${secret}\\n`),
          addresses: () => Effect.succeed([{ address: "93.184.216.34", family: 4 }]),
          send: (prepared, received, address) =>
            Effect.sync(() => {
              assert.strictEqual(prepared.url.hostname, "api.example.com")
              assert.strictEqual(prepared.header, "Authorization")
              assert.strictEqual(prepared.prefix, "Bearer ")
              assert.strictEqual(received, secret)
              assert.deepStrictEqual(address, { address: "93.184.216.34", family: 4 })
              const body = `ok ${secret} then ${secret}`
              return { status: 200, body, bytes: Buffer.byteLength(body) }
            }),
        },
      )

      assert.deepStrictEqual(result, {
        ok: true,
        status: 200,
        destination: "https://api.example.com/v1/me",
        reference: "op://Personal/Example/credential",
        responseBytes: Buffer.byteLength(`ok ${secret} then ${secret}`),
        redactions: 2,
        body: "ok [REDACTED] then [REDACTED]",
      })
      assert.notInclude(JSON.stringify(result), secret)
    }),
  )

  it.effect("rejects a private destination before resolving the credential", () =>
    Effect.gen(function* () {
      let reads = 0
      const result = yield* Effect.either(
        Request.requestWith(
          {
            url: "https://internal.example/",
            reference: "op://Personal/Example/credential",
            header: "Authorization",
            prefix: "Bearer ",
          },
          {
            resolve: () =>
              Effect.sync(() => {
                reads += 1
                return secret
              }),
            addresses: () =>\n              Effect.succeed([\n                { address: "93.184.216.34", family: 4 },\n                { address: "127.0.0.1", family: 4 },\n              ]),
            send: () => Effect.fail(Op.fail("must not send")),
          },
        ),
      )
      assert.strictEqual(result._tag, "Left")
      assert.strictEqual(reads, 0)
    }),
  )

  for (const options of [
    { url: "http://api.example.com/", header: "Authorization", prefix: "Bearer " },
    { url: "https://user@api.example.com/", header: "Authorization", prefix: "Bearer " },
    { url: "https://api.example.com:8443/", header: "Authorization", prefix: "Bearer " },
    { url: "https://api.example.com/#fragment", header: "Authorization", prefix: "Bearer " },
    { url: "https://api.example.com/", header: "Cookie", prefix: "" },
  ]) {
    it.effect(`rejects unsafe request shape: ${JSON.stringify(options)}`, () =>
      Effect.gen(function* () {
        let touched = false
        const result = yield* Effect.either(
          Request.requestWith(
            {
              ...options,
              reference: "op://Personal/Example/credential",
            },
            {
              resolve: () => {
                touched = true
                return Effect.succeed(secret)
              },
              addresses: () => {
                touched = true
                return Effect.succeed([{ address: "93.184.216.34", family: 4 }])
              },
              send: () => {
                touched = true
                return Effect.succeed({ status: 200, body: "", bytes: 0 })
              },
            },
          ),
        )
        assert.strictEqual(result._tag, "Left")
        assert.isFalse(touched)
      }),
    )
  }

  it("redacts JSON-escaped echoes", async () => {
    const quoted = 'fictional-"quoted"-secret'
    const result = await Effect.runPromise(
      Request.requestWith(
        {
          url: "https://api.example.com/v1/me",
          reference: "op://Personal/Example/credential",
          header: "X-API-Key",
          prefix: "",
        },
        {
          resolve: () => Effect.succeed(quoted),
          addresses: () => Effect.succeed([{ address: "1.1.1.1", family: 4 }]),
          send: () => {
            const body = JSON.stringify({ token: quoted })
            return Effect.succeed({ status: 200, body, bytes: Buffer.byteLength(body) })
          },
        },
      ),
    )
    assert.strictEqual(result.body, '{"token":"[REDACTED]"}')
    assert.strictEqual(result.redactions, 1)
    assert.notInclude(JSON.stringify(result), quoted)
  })

  it("exposes the command and flags without touching op or the network", async () => {
    const box = await sandbox({ op: "#!/bin/sh\\nexit 71\\n" })
    try {
      const result = await box.run(["request", "--help"])
      assert.strictEqual(result.code, 0)
      for (const value of ["<url>", "--secret", "--header", "--prefix"]) assert.include(result.stdout, value)
      assert.deepStrictEqual(await box.calls(), [])
    } finally {
      await box.close()
    }
  })

  it("classifies private and public addresses conservatively", () => {
    for (const address of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "203.0.113.5"]) {
      assert.isFalse(isPublicAddress({ address, family: 4 }))
    }
    assert.isTrue(isPublicAddress({ address: "1.1.1.1", family: 4 }))
    assert.isFalse(isPublicAddress({ address: "::1", family: 6 }))
    assert.isFalse(isPublicAddress({ address: "fe80::1", family: 6 }))
    assert.isTrue(isPublicAddress({ address: "2606:4700:4700::1111", family: 6 }))
  })
})
