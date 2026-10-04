import { Effect } from "effect"
import { Lease } from "./lease.js"
import { Request, type Options } from "./request.js"

export const request = Effect.fn("LeasedRequest.request")(function* (leaseId: string, options: Options) {
  const binding = yield* Request.describe(options)

  // Check local authority before DNS or 1Password.
  yield* Lease.authorize(leaseId, binding)

  // Request validates all destination addresses before invoking this resolver.
  // The resolver version-checks, atomically claims a use, reads plaintext, then
  // version-checks again before returning the value to the private executor.
  const result = yield* Request.executeWithResolver(options, Lease.resolver(leaseId, binding))
  const lease = yield* Lease.status(leaseId)

  return {
    ...result,
    lease: {
      id: lease.id,
      principal: lease.principal,
      expiresAt: lease.expiresAt,
      usesRemaining: lease.usesRemaining,
    },
  }
})

export * as LeasedRequest from "./request-leased.js"
