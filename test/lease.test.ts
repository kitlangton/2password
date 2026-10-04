import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Lease } from "../src/lease.js"
import type { Binding } from "../src/request.js"

const resource = { id: "i".repeat(26), version: 7 }
const binding: Binding = {
  capability: "request",
  method: "GET",
  reference: "op://Personal/Example API Key/credential",
  destination: "https://api.example.com/v1/me",
  destinationFingerprint: "a".repeat(64),
  header: "Authorization",
  prefix: "Bearer ",
}

const fixture = async () => {
  const directory = await mkdtemp(join(tmpdir(), "2password-lease-"))
  return {
    path: join(directory, "leases.sqlite"),
    close: () => rm(directory, { recursive: true, force: true }),
  }
}

const grant = (path: string, uses = 1, expiresIn = "10m") =>
  Lease.grantWith({ ...binding }, { path, uses, expiresIn }, () => Effect.succeed(resource))

describe("leases", () => {
  it("binds authority and atomically exhausts a use budget", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path, 2))
      assert.strictEqual(created.usesRemaining, 2)
      assert.strictEqual(created.itemVersion, 7)
      assert.strictEqual(created.destinationFingerprint, binding.destinationFingerprint)

      const authorized = await Effect.runPromise(Lease.authorize(created.id, binding, { path: f.path }))
      assert.strictEqual(authorized.principal, created.principal)

      const first = await Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path }))
      assert.strictEqual(first.usesRemaining, 1)
      const second = await Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path }))
      assert.strictEqual(second.usesRemaining, 0)

      const replay = await Effect.runPromise(
        Effect.either(Lease.claim(created.id, binding, resource, { path: f.path })),
      )
      assert.strictEqual(replay._tag, "Left")
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("denies binding and credential-version mismatches without spending a use", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path))
      const wrongBinding = { ...binding, destinationFingerprint: "b".repeat(64) }

      assert.strictEqual(
        (await Effect.runPromise(Effect.either(Lease.authorize(created.id, wrongBinding, { path: f.path }))))._tag,
        "Left",
      )
      assert.strictEqual(
        (
          await Effect.runPromise(
            Effect.either(Lease.claim(created.id, binding, { ...resource, version: 8 }, { path: f.path })),
          )
        )._tag,
        "Left",
      )
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })

  it("allows exactly one concurrent claim for a one-use lease", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path))
      const attempts = await Promise.allSettled([
        Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path })),
        Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path })),
      ])
      assert.strictEqual(attempts.filter(({ status }) => status === "fulfilled").length, 1)
      assert.strictEqual(attempts.filter(({ status }) => status === "rejected").length, 1)
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("revokes immediately and keeps revocation idempotently closed", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path, 3))
      const revoked = await Effect.runPromise(Lease.revoke(created.id, { path: f.path }))
      assert.isTrue(revoked.revoked)
      assert.strictEqual(
        (await Effect.runPromise(Effect.either(Lease.authorize(created.id, binding, { path: f.path }))))._tag,
        "Left",
      )
      assert.strictEqual(
        (await Effect.runPromise(Effect.either(Lease.revoke(created.id, { path: f.path }))))._tag,
        "Left",
      )
    } finally {
      await f.close()
    }
  })

  it("burns the claim and withholds the secret if the credential version changes during use", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path))
      let inspections = 0
      let reads = 0
      const resolve = Lease.resolverWith(created.id, binding, { path: f.path }, {
        inspect: () =>
          Effect.sync(() => {
            inspections += 1
            return inspections === 1 ? resource : { ...resource, version: resource.version + 1 }
          }),
        read: () =>
          Effect.sync(() => {
            reads += 1
            return "fictional-private-value"
          }),
      })

      const result = await Effect.runPromise(Effect.either(resolve(binding.reference)))
      assert.strictEqual(result._tag, "Left")
      assert.strictEqual(reads, 1)
      assert.strictEqual(inspections, 2)
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("expires without spending or reviving a lease", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path, 1, "1s"))
      await new Promise((resolve) => setTimeout(resolve, 1100))
      assert.strictEqual(
        (await Effect.runPromise(Effect.either(Lease.authorize(created.id, binding, { path: f.path }))))._tag,
        "Left",
      )
      assert.strictEqual(
        (await Effect.runPromise(Effect.either(Lease.claim(created.id, binding, resource, { path: f.path }))))._tag,
        "Left",
      )
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })

  it("rejects overbroad lifetimes and budgets before inspecting 1Password", async () => {
    const f = await fixture()
    try {
      let inspected = false
      const inspect = () => {
        inspected = true
        return Effect.succeed(resource)
      }
      const ttl = await Effect.runPromise(
        Effect.either(Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "2h" }, inspect)),
      )
      const uses = await Effect.runPromise(
        Effect.either(Lease.grantWith(binding, { path: f.path, uses: 11, expiresIn: "10m" }, inspect)),
      )
      assert.strictEqual(ttl._tag, "Left")
      assert.strictEqual(uses._tag, "Left")
      assert.isFalse(inspected)
    } finally {
      await f.close()
    }
  })
})
