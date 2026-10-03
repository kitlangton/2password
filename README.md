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
```

Run `2password --help` to see all commands.

## Fewer prompts

- **One prompt per command.** `find` with many queries and env files with many references each need a single 1Password approval.
- **No prompts at all.** Give your agent its own vault and a service account whose token lives in macOS Keychain:

  ```sh
  2password service-account setup --vault Automation --create-vault --write --save-vault Personal
  ```

## Safety

- Only `read` and `env resolve` intentionally return or materialize a secret from 2password.
- `run` and `env run` inject plaintext into the selected child process. 2password does not print the value, but the child can; only use them with commands you trust with that credential.
- New secrets come in through the clipboard or a pipe, never as arguments. Every write is read back and checked.
- Writes are never retried automatically.

MIT
