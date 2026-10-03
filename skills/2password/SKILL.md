---
name: 2password
description: Use for any password, API key, token, credential, secret, or 1Password task, including finding credentials, injecting them into commands or env files, saving new API keys, checking or updating login passwords, auditing vaults, and setting up unattended access. Prefer the 2password CLI over raw op whenever it covers the task.
---

# 2password

`2password` wraps the 1Password CLI (`op`) so you can work with secrets without seeing them, and with as few 1Password prompts as possible. All output is JSON.

## Rules

- Never print, log, summarize, or repeat secret values. Pass `op://` references around instead.
- `run` and `env run` give the target child process plaintext. Use them only with the command that actually needs the credential; never route a secret through a helper whose purpose is to print, encode, transform, or forward it. Output masking is best effort.
- Treat `read` and `env resolve` as explicit escape hatches because they intentionally expose plaintext.
- Any 1Password call may show the user an approval prompt. Batch work into one command: many queries in one `find`, many references in one env file.
- Never run `op whoami` or any other preflight check. Just run the command; the desktop app authorizes it when needed.
- Never retry a write that failed or reported "unverified". Run `find` first to check whether it already happened.

## Find credentials

```bash
2password find openai anthropic "github actions"   # many queries, one prompt
2password find stripe --vault Work --account my.1password.com
```

Returns titles, vaults, field names, and `op://` references. It never returns values.

## Use credentials

```bash
2password run --env "OPENAI_API_KEY=op://Personal/OpenAI API Key/credential" -- bun run dev
2password env write .env.tpl "OPENAI_API_KEY=op://Personal/OpenAI API Key/credential" "STRIPE_KEY=op://Work/Stripe API Key/credential"
2password env run .env.tpl -- bun run dev       # preferred: no plaintext on disk
2password env resolve .env.tpl --output .env    # only when a real file is required (mode 0600)
2password read "op://Personal/OpenAI API Key/credential"   # last resort: prints the value
```

All references in a template resolve with one prompt. Never loop over `read`. A `.env.tpl` that holds only `op://` references is safe to inspect; a resolved `.env` is plaintext.

## Save a new API key

```bash
2password create api-credential --title "OpenAI API Key" --vault Personal --clipboard
some-command-that-prints-a-key | 2password create api-credential --title "OpenAI API Key" --vault Personal --stdin
```

- `--vault` is required. Use the vault the user names, or their documented default; ask if neither exists.
- Never put the value in an argument, a command substitution, or a temporary file, and never read the clipboard into the conversation first.
- Optional `--url`, `--notes`, and `--account` take non-secret metadata only.
- Success means exit 0 and `"verified": true`. Reuse the returned `ref`; don't `read` it to double-check.
- Duplicate titles in the vault are refused, and nothing is ever overwritten.

## Check or update a login password

```bash
2password password "Example Airline" --vault Personal --clipboard           # compare only
2password password "Example Airline" --vault Personal --clipboard --apply   # update, then verify
```

The command refuses logins that have passkeys or unnamed imported fields. Use `--repair-imported-fields` only after the user approves it.

## Audit a vault

```bash
2password inventory --vault Work   # item and field metadata, never values or URL query strings
2password audit --vault Personal   # duplicate titles, untagged machine credentials, old logins, transient URLs
```

Treat findings as candidates for review. Propose renames or changes, and only make them after the user approves.

## No prompts: service account (macOS)

If the user is tired of approval prompts, suggest a service account. Only set one up when the user asks.

```bash
2password service-account setup --vault Automation --create-vault --write --save-vault Personal
```

After setup, every command authenticates silently with a token stored in macOS Keychain, but it can only reach the Automation vault. Keep the credentials agents use in that vault.

- `2password --desktop <command>` uses the normal desktop login, for example to reach other vaults.
- `service-account status | connect --clipboard | recover | forget`. `forget` removes only this Mac's copy; it doesn't revoke the account.
- If setup fails partway, don't rerun it. Run `2password service-account status`.
- `OP_SERVICE_ACCOUNT_TOKEN` in the environment overrides the saved account (Linux, CI).
- `run` and `env run` remove the service-account token from the child process's environment.

## Item conventions

- API keys use the API Credential category, the built-in `credential` field, and a title like `<Provider> API Key` or `<Provider> <Purpose> API Key`.
- Logins use the built-in `password` field and a title like `<Provider>` or `<Provider> <Account>`.
- The vault shows who owns the item, so don't repeat the vault name in the title. Keep one current secret per item.

## Everything else

Use raw `op` for other item categories, editing, moving, sharing, deleting, and vault management. Pass plaintext through JSON templates on stdin, never in arguments. After discovery, refer to items and vaults by ID.
