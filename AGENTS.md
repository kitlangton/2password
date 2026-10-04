# 2password

A Bun + Effect v4 CLI over 1Password's `op`.

## Purpose

Let a coding agent use credentials as freely as a trusted teammate would, without the human babysitting it and without the secret ever entering the model's context. `op` was built for a person at a terminal; agents make many quick calls from fresh shells, and everything they read lands in a transcript. 2password adapts `op` to that user.

Optimize, in order:

1. **Human interruptions per task.** At most one approval per task, and zero with a service account. Every prompt, unlock, or stuck app counts against us.
2. **Plaintext in the model's context.** Zero by default. Agents pass `op://` references; revealing a value is always an explicit, named command.
3. **Agent success on the first try.** One obvious command per goal, compact JSON, and errors that say what to do next.
4. **Trustworthy writes.** Never lose, duplicate, or silently overwrite a credential.

Not goals: being a vault, being a sandbox (a child given a secret by `run` can do anything with it), or replacing `op` for administration. Keep the interface small: it is the product.

```sh
bun install
bun run check                 # format check, lint, typecheck, tests: what CI runs
bun run format                # oxfmt
bun run test                  # never touches real 1Password, clipboard, or Keychain
bun run bin/2password --help
```

## Map

```
bin/2password               entry point
src/cli.ts                  command table: flags -> module call -> JSON on stdout; no logic
src/op.ts                   the subprocess seam: op / json / exec, privateInput, Failure, Credentials
src/auth.ts                 which credentials op runs with (desktop, env token, Keychain token) and their local storage
src/keychain.jxa.js         native Keychain bridge, run through osascript; the token crosses stdin only
src/credential.win.ps1      Windows counterpart: DPAPI-encrypted token file, run through powershell; stdin/stdout only
src/without-token.ts        Windows replacement for `env -u OP_SERVICE_ACCOUNT_TOKEN` in run and env run
src/discover.ts             find (with near-miss suggestions), inventory, audit
src/doctor.ts               doctor: versions and setup, never authenticates
src/env.ts                  read, run, env write/resolve/run
src/create.ts               create api-credential
src/password.ts             password compare/update
src/request.ts              destination-bound HTTPS private executor
src/lease-store.ts          non-secret principal, bindings, expiry, atomic use counters
src/lease.ts                1Password version pinning and claim-before-read policy
src/request-leased.ts       lease authority wrapped around request execution
src/service-account.ts      service-account setup/connect/status/recover/forget
src/arguments.ts            keeps arguments after `--` away from the flag parser
skills/2password/SKILL.md   the agent skill we ship; keep it in sync with the CLI
test/sandbox.ts             runs the real CLI against fake executables (on Windows via test/shim.ts and Git's sh)
```

## Invariants

These are security properties. Do not weaken them.

1. Secrets never appear in argv, stdout (except `read` and `env resolve`), stderr, or error messages. Plaintext reaches op only through `Op.op(args, { input })`.
2. op's stdout never reaches an error. Any op call that sends plaintext (`input`) or reveals it (`--reveal`, `service-account create`) also passes `failure: "..."`, which suppresses op's stderr and replaces every error with that fixed message.
3. Writes run once, then the result is read back and compared. A failure after a write must say it is unverified and must not be retried. Never add automatic retries.
4. Never preflight with `op whoami`; the requested operation is the capability check.
5. Every op call may prompt the user, so batch: `find` and `inventory` use one `item get -`, and env resolution uses one `op run`.
6. If the saved service account fails, report the failure. Never fall back to desktop authentication.
7. Results are JSON on stdout and notices go to stderr. Every expected error is an `Op.Failure`, printed as `2password: <message>` with exit code 1.
8. `request` validates the full HTTPS destination and all resolved addresses before reading a credential, rejects any special/private answer, pins the connection to one validated address, follows no redirects, caps the response, keeps its body private, and returns only non-secret receipt metadata.
9. CLI `request` requires a matching lease. Local authorization happens before DNS; the credential version is checked before an atomic use claim; the claim is consumed before plaintext resolution; the version is checked again before anything can be sent.
10. Replay, expiry, revocation, binding mismatch, stale version, read failure after claim, or mid-use rotation fail closed. Never refund or automatically retry a claimed use.
11. `lease approve` is the human/admin UX boundary: interactive terminal only, desktop-authenticated, at most 1 hour and 10 uses. This is not per-agent OS isolation; same-user local code can still tamper with local state.

## Changing things

- Put logic in a module function that returns a plain object and fails with `new Op.Failure({ message })`. In `cli.ts`, only parse flags and `print` the result.
- Test through `sandbox()` with a fake `op` (see `test/fixtures/`). Assert the exact op calls, and assert that fictional sentinel secrets never appear in stdout, stderr, or recorded calls.
- For a user-facing change, update `skills/2password/SKILL.md`. Update `README.md` only if the quick start changes; keep it short.
- `bun run test:keychain` is an opt-in test against the real Keychain (macOS) or DPAPI store (Windows), using a disposable item.

## Release

Published to npm as `2password` by `.github/workflows/release.yml` (npm trusted publishing, so no tokens). The skill installs from this repo with `bunx skills add kitlangton/2password`.

```sh
npm version patch      # or minor; commits and tags vX.Y.Z
git push --follow-tags # CI checks, publishes, and creates the GitHub release
```
