import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { LeaseStore } from "../src/lease-store.js"
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
  const directory = await mkdtemp(join(tmpdir(), "2password-lease-store-"))
  return {
    path: join(directory, "leases.sqlite"),
    close: () => rm(directory, { recursive: true, force: true }),
  }
}

const failure = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.map(() => false),
    Effect.catch(() => Effect.succeed(true)),
  )

describe("lease store", () => {
  it("persists a stable local principal and exact authority binding", async () => {
    const f = await fixture()
    try {
      const first = await Effect.runPromise(
        LeaseStore.grant(binding, resource, { path: f.path, uses: 2, expiresAt: Date.now() + 60_000 }),
      )
      const second = await Effect.runPromise(
        LeaseStore.grant(binding, resource, { path: f.path, uses: 1, expiresAt: Date.now() + 60_000 }),
      )
      assert.strictEqual(first.principal, second.principal)
      assert.strictEqual(first.itemVersion, 7)
      assert.strictEqual(first.destinationFingerprint, binding.destinationFingerprint)
      assert.strictEqual(first.useBudget, 2)
      assert.strictEqual(first.usesRemaining, 2)
    } finally {
      await f.close()
    }
  })

  it("denies binding or resource-version mismatch without spending a use", async () => {
    const f = await fixture()
    try {
      const lease = await Effect.runPromise(
        LeaseStore.grant(binding, resource, { path: f.path, uses: 1, expiresAt: Date.now() + 60_000 }),
      )
      assert.isTrue(
        await Effect.runPromise(
          failure(
            LeaseStore.authorize(lease.id, { ...binding, destinationFingerprint: "b".repeat(64) }, { path: f.path }),
          ),
        ),
      )
      assert.isTrue(
        await Effect.runPromise(
          failure(LeaseStore.claim(lease.id, binding, { ...resource, version: 8 }, { path: f.path })),
        ),
      )
      assert.strictEqual((await Effect.runPromise(LeaseStore.status(lease.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })

  it("allows exactly one concurrent claim for a one-use lease", async () => {
    const f = await fixture()
    try {
      const lease = await Effect.runPromise(
        LeaseStore.grant(binding, resource, { path: f.path, uses: 1, expiresAt: Date.now() + 60_000 }),
      )
      const attempts = await Promise.allSettled([
        Effect.runPromise(LeaseStore.claim(lease.id, binding, resource, { path: f.path })),
        Effect.runPromise(LeaseStore.claim(lease.id, binding, resource, { path: f.path })),
      ])
      assert.strictEqual(attempts.filter(({ status }) => status === "fulfilled").length, 1)
      assert.strictEqual(attempts.filter(({ status }) => status === "rejected").length, 1)
      assert.strictEqual((await Effect.runPromise(LeaseStore.status(lease.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("revokes immediately and expiry never consumes a use", async () => {
    const f = await fixture()
    try {
      const revoked = await Effect.runPromise(
        LeaseStore.grant(binding, resource, { path: f.path, uses: 2, expiresAt: Date.now() + 60_000 }),
      )
      assert.isTrue((await Effect.runPromise(LeaseStore.revoke(revoked.id, { path: f.path }))).revoked)
      assert.isTrue(await Effect.runPromise(failure(LeaseStore.authorize(revoked.id, binding, { path: f.path }))))

      const expired = await Effect.runPromise(
        LeaseStore.grant(binding, resource, { path: f.path, uses: 1, expiresAt: Date.now() + 50 }),
      )
      await new Promise((resolve) => setTimeout(resolve, 75))
      assert.isTrue(await Effect.runPromise(failure(LeaseStore.claim(expired.id, binding, resource, { path: f.path }))))
      assert.strictEqual((await Effect.runPromise(LeaseStore.status(expired.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })

  it("rejects malformed grants before creating authority", async () => {
    const f = await fixture()
    try {
      assert.isTrue(
        await Effect.runPromise(
          failure(LeaseStore.grant(binding, resource, { path: f.path, uses: 0, expiresAt: Date.now() + 60_000 })),
        ),
      )
      assert.isTrue(
        await Effect.runPromise(
          failure(LeaseStore.grant(binding, resource, { path: f.path, uses: 1, expiresAt: Date.now() - 1 })),
        ),
      )
    } finally {
      await f.close()
    }
  })
})
