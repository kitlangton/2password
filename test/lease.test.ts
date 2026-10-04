import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Lease } from "../src/lease.js"
import { LeaseStore } from "../src/lease-store.js"
import { Op } from "../src/op.js"
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
  const directory = await mkdtemp(join(tmpdir(), "2password-lease-policy-"))
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

describe("lease policy", () => {
  it("bounds lifetime and use count before inspecting custody", async () => {
    const f = await fixture()
    try {
      let inspected = false
      const inspect = () => {
        inspected = true
        return Effect.succeed(resource)
      }
      assert.isTrue(
        await Effect.runPromise(
          failure(Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "2h" }, inspect)),
        ),
      )
      assert.isTrue(
        await Effect.runPromise(
          failure(Lease.grantWith(binding, { path: f.path, uses: 11, expiresIn: "10m" }, inspect)),
        ),
      )
      assert.isFalse(inspected)
    } finally {
      await f.close()
    }
  })

  it("pins the inspected resource version into the grant", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(
        Lease.grantWith(binding, { path: f.path, uses: 2, expiresIn: "10m" }, () => Effect.succeed(resource)),
      )
      assert.strictEqual(created.itemId, resource.id)
      assert.strictEqual(created.itemVersion, resource.version)
      assert.strictEqual(created.useBudget, 2)
    } finally {
      await f.close()
    }
  })

  it("claims authority before reading plaintext", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(
        Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "10m" }, () => Effect.succeed(resource)),
      )
      let inspections = 0
      let readObservedRemaining = -1
      const resolve = Lease.resolverWith(created.id, binding, { path: f.path }, {
        inspect: () =>
          Effect.sync(() => {
            inspections += 1
            return resource
          }),
        read: () =>
          Effect.gen(function* () {
            readObservedRemaining = (yield* LeaseStore.status(created.id, { path: f.path })).usesRemaining
            return "fictional-private-value"
          }),
      })

      assert.strictEqual(await Effect.runPromise(resolve(binding.reference)), "fictional-private-value")
      assert.strictEqual(readObservedRemaining, 0)
      assert.strictEqual(inspections, 2)
    } finally {
      await f.close()
    }
  })

  it("burns a claimed use when plaintext resolution fails", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(
        Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "10m" }, () => Effect.succeed(resource)),
      )
      const resolve = Lease.resolverWith(created.id, binding, { path: f.path }, {
        inspect: () => Effect.succeed(resource),
        read: () => Effect.fail(Op.fail("fictional read failure")),
      })
      assert.isTrue(await Effect.runPromise(failure(resolve(binding.reference))))
      assert.strictEqual((await Effect.runPromise(LeaseStore.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("withholds a rotated credential after the use was claimed", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(
        Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "10m" }, () => Effect.succeed(resource)),
      )
      let inspections = 0
      const resolve = Lease.resolverWith(created.id, binding, { path: f.path }, {
        inspect: () =>
          Effect.sync(() => {
            inspections += 1
            return inspections === 1 ? resource : { ...resource, version: resource.version + 1 }
          }),
        read: () => Effect.succeed("fictional-private-value"),
      })

      assert.isTrue(await Effect.runPromise(failure(resolve(binding.reference))))
      assert.strictEqual(inspections, 2)
      assert.strictEqual((await Effect.runPromise(LeaseStore.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("rejects a different credential before inspection or claim", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(
        Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "10m" }, () => Effect.succeed(resource)),
      )
      let touched = false
      const resolve = Lease.resolverWith(created.id, binding, { path: f.path }, {
        inspect: () => {
          touched = true
          return Effect.succeed(resource)
        },
        read: () => {
          touched = true
          return Effect.succeed("fictional-private-value")
        },
      })
      assert.isTrue(await Effect.runPromise(failure(resolve("op://Personal/Other/credential"))))
      assert.isFalse(touched)
      assert.strictEqual((await Effect.runPromise(LeaseStore.status(created.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })
})
