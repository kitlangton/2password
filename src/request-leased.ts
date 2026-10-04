import { Effect } from "effect"
import { Lease } from "./lease.js"
import { Request, type Options } from "./request.js"

export const request = Effect.fn("LeasedRequest.request")(function* (
  leaseId: string,
  options: Options,
) {
  const binding = yield* Request.describe(options)

  // Identity/binding/expiry/use checks happen before DNS, so an unauthorized caller
  // cannot use the request primitive as a DNS oracle.
  yield* Lease.authorize(leaseId, binding)

  // Request validates every resolved address before invoking this resolver.
  // The resolver checks credential version, atomically consumes one use, reads the
  // value, and checks the version again before returning it to the private executor.
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
