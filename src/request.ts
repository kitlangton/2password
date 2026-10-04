import { Effect } from "effect"
import { lookup } from "node:dns/promises"
import { request as httpsRequest } from "node:https"
import { BlockList } from "node:net"
import { Op } from "./op.js"

export interface Options {
  readonly url: string
  readonly reference: string
  readonly header: string
  readonly prefix: string
}

export interface Address {
  readonly address: string
  readonly family: 4 | 6
}

interface Prepared {
  readonly url: URL
  readonly header: "Authorization" | "X-API-Key"
  readonly prefix: string
}

interface RawResponse {
  readonly status: number
  readonly body: string
  readonly bytes: number
}

export interface Dependencies {
  readonly resolve: (reference: string) => Effect.Effect<string, Op.Failure>
  readonly addresses: (hostname: string) => Effect.Effect<ReadonlyArray<Address>, Op.Failure>
  readonly send: (prepared: Prepared, secret: string, address: Address) => Effect.Effect<RawResponse, Op.Failure>
}

const blocked = new BlockList()
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(network, prefix, "ipv4")
}
for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["2001:db8::", 32],
] as const) {
  blocked.addSubnet(network, prefix, "ipv6")
}

const responseLimit = 64 * 1024
const fail = (message: string) => Op.fail(message)

export const isPublicAddress = ({ address, family }: Address): boolean =>
  family === 4
    ? !blocked.check(address, "ipv4")
    : !address.toLowerCase().startsWith("::ffff:") && !blocked.check(address, "ipv6")

const hostname = (url: URL) => (url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname)

const prepare = (options: Options): Prepared => {
  let url: URL
  try {
    url = new URL(options.url)
  } catch {
    throw fail("Request URL must be a valid HTTPS URL")
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    (url.port !== "" && url.port !== "443") ||
    url.hash !== ""
  ) {
    throw fail("Request URL must use HTTPS on port 443 without userinfo or a fragment")
  }
  if (options.url.length > 2048) throw fail("Request URL is too long")
  if (!options.reference.startsWith("op://") || /[\r\n]/.test(options.reference)) {
    throw fail("Request secret must be an op:// reference")
  }
  const normalized = options.header.toLowerCase()
  const header =
    normalized === "authorization"
      ? ("Authorization" as const)
      : normalized === "x-api-key"
        ? ("X-API-Key" as const)
        : undefined
  if (header === undefined) throw fail("Request secret header must be Authorization or X-API-Key")
  if (/[\r\n]/.test(options.prefix) || options.prefix.length > 64) {
    throw fail("Request header prefix is invalid")
  }
  return { url, header, prefix: options.prefix }
}

const addresses = (host: string) =>
  Effect.tryPromise({
    try: () => lookup(host, { all: true, verbatim: true }),
    catch: () => fail("Could not resolve request destination"),
  }).pipe(
    Effect.flatMap((results) => {
      const resolved = results.flatMap(({ address, family }): ReadonlyArray<Address> =>
        family === 4 || family === 6 ? [{ address, family }] : [],
      )
      return resolved.length === 0
        ? Effect.fail(fail("Request destination did not resolve"))
        : Effect.succeed(resolved)
    }),
  )

const resolve = (reference: string) =>
  Op.op(["read", reference], {
    failure: "Could not resolve request credential (1Password details suppressed)",
  })

const send = (prepared: Prepared, secret: string, address: Address) =>
  Effect.tryPromise({
    try: () =>
      new Promise<RawResponse>((resolvePromise, rejectPromise) => {
        let settled = false
        const reject = () => {
          if (settled) return
          settled = true
          rejectPromise(new Error("request failed"))
        }
        const outbound = httpsRequest(
          prepared.url,
          {
            method: "GET",
            headers: {
              [prepared.header]: `${prepared.prefix}${secret}`,
              "Accept-Encoding": "identity",
            },
            lookup: (_host, _options, callback) => callback(null, address.address, address.family),
          },
          (response) => {
            const chunks: Array<Buffer> = []
            let bytes = 0
            response.on("data", (chunk: Buffer | string) => {
              if (settled) return
              const buffer = typeof chunk === "string" ? Buffer.from(chunk) : chunk
              bytes += buffer.length
              if (bytes > responseLimit) {
                outbound.destroy()
                reject()
                return
              }
              chunks.push(buffer)
            })
            response.on("end", () => {
              if (settled) return
              settled = true
              resolvePromise({
                status: response.statusCode ?? 0,
                body: Buffer.concat(chunks, bytes).toString("utf8"),
                bytes,
              })
            })
            response.on("error", reject)
          },
        )
        outbound.setTimeout(15_000, () => {
          outbound.destroy()
          reject()
        })
        outbound.on("error", reject)
        outbound.end()
      }),
    catch: () => fail("HTTPS request failed (details suppressed)"),
  })

const redact = (body: string, secret: string) => {
  const variants = [...new Set([secret, JSON.stringify(secret).slice(1, -1)])].filter(Boolean)
  let value = body
  let redactions = 0
  for (const variant of variants) {
    const parts = value.split(variant)
    redactions += parts.length - 1
    value = parts.join("[REDACTED]")
  }
  return { value, redactions }
}

export const requestWith = Effect.fn("Request.requestWith")(function* (options: Options, dependencies: Dependencies) {
  const prepared = yield* Effect.try({\n    try: () => prepare(options),\n    catch: (error) => (error instanceof Op.Failure ? error : fail("Could not prepare HTTPS request")),\n  })
  const resolved = yield* dependencies.addresses(hostname(prepared.url))
  if (resolved.some((address) => !isPublicAddress(address))) {
    return yield* fail("Request destination resolved to a non-public address")
  }
  const address = resolved[0]
  if (address === undefined) return yield* fail("Request destination did not resolve")

  const secret = yield* dependencies.resolve(options.reference)
  if (secret.length === 0 || /[\r\n]/.test(secret)) {
    return yield* fail("Request credential cannot be used in an HTTP header")
  }

  const response = yield* dependencies.send(prepared, secret, address)
  const body = redact(response.body, secret)
  return {
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    destination: `${prepared.url.origin}${prepared.url.pathname}`,
    reference: options.reference,
    responseBytes: response.bytes,
    redactions: body.redactions,
    body: body.value,
  }
})

export const request = (options: Options) =>
  requestWith(options, {
    resolve,
    addresses,
    send,
  })

export * as Request from "./request.js"
