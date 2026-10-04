# 2password

A Bun + Effect v4 CLI over 1Password's `op`. Goal: agents use secrets without seeing them, with the fewest possible 1Password prompts.

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
src/discover.ts             find, inventory, audit
src/env.ts                  read, run, env write/resolve/run
src/create.ts               create api-credential
src/password.ts             password compare/update
src/request.ts              destination-bound HTTPS GET with secret echo redaction
src/service-account.ts      service-account setup/connect/status/recover/forget
src/arguments.ts            keeps arguments after `--` away from the flag parser
skills/2password/SKILL.md   the agent skill we ship; keep it in sync with the CLI
test/sandbox.ts             runs the real CLI against fake executables
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
8. `request` validates the complete destination and resolves all DNS answers before reading a credential, rejects any non-public answer, pins the connection to one validated address, follows no redirects, bounds the response, keeps the response body private, and reports only non-secret receipt metadata including exact-secret echo counts.

## Changing things

- Put logic in a module function that returns a plain object and fails with `new Op.Failure({ message })`. In `cli.ts`, only parse flags and `print` the result.
- Test through `sandbox()` with a fake `op` (see `test/fixtures/`). Assert the exact op calls, and assert that fictional sentinel secrets never appear in stdout, stderr, or recorded calls.
- For a user-facing change, update `skills/2password/SKILL.md`. Update `README.md` only if the quick start changes; keep it short.
- `bun run test:keychain` is an opt-in macOS test against the real Keychain, using a disposable item.

## Release

Published to npm as `2password` by `.github/workflows/release.yml` (npm trusted publishing, so no tokens). The skill installs from this repo with `bunx skills add kitlangton/2password`.

```sh
npm version patch      # or minor; commits and tags vX.Y.Z
git push --follow-tags # CI checks, publishes, and creates the GitHub release
```
