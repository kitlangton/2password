# 2password

1Password for coding agents. Your agent finds, uses, and saves secrets without ever seeing them, and asks you to approve far less often.

## Install

Requires [Bun](https://bun.sh) and the [1Password CLI](https://developer.1password.com/docs/cli/get-started/).

```sh
bun add -g 2password                  # the CLI
bunx skills add kitlangton/2password  # teaches your agent to use it
```

## Use

```sh
2password find openai stripe        # returns op:// references, never values
2password run --env "OPENAI_API_KEY=op://Personal/OpenAI API Key/credential" -- bun dev
2password env run .env.tpl -- bun dev
2password create api-credential --title "OpenAI API Key" --vault Personal --clipboard
# human/admin terminal: approve exact use
2password lease approve https://api.example.com/v1/me --secret "op://Personal/Example API Key/credential" --expires-in 10m --uses 1

# agent: consume the returned lease ID
2password request https://api.example.com/v1/me --secret "op://Personal/Example API Key/credential" --lease <lease-id>
```

Run `2password --help` to see all commands.

## Fewer prompts

- **One prompt per command.** `find` with many queries and env files with many references each need a single 1Password approval.
- **No prompts at all.** Give your agent its own vault and a service account whose token lives in macOS Keychain:

  ```sh
  2password service-account setup --vault Automation --create-vault --write --save-vault Personal
  ```

## Safety

- Only `read` and `env resolve` ever intentionally output a secret.
- `request` requires a short-lived lease bound to the local principal, exact credential/version, HTTPS destination, header shape, expiry, and atomic use budget. Authorization happens before DNS; the use is claimed before the secret is resolved or sent.
- The response body never returns to the agent. Only bounded receipt metadata is emitted.
- `lease approve` is intentionally interactive + desktop-authenticated. It is an approval mechanism, not a claim that this CLI provides per-agent OS isolation.
- New secrets come in through the clipboard or a pipe, never as arguments. Every write is read back and checked.
- Writes are never retried automatically.

MIT
