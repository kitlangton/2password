# Security

2password exists to keep secret plaintext out of agent-visible channels during normal credential workflows.

## Boundary

- Discovery returns metadata and `op://` references, not values.
- New secret values cross stdin or the clipboard, never argv.
- `read` and `env resolve` intentionally reveal or materialize plaintext and should be treated as explicit escape hatches.
- `run` and `env run` resolve plaintext into the child process environment. 1Password masks matching stdout and stderr by default, but that masking is best effort; the child process itself possesses the secret.
- 2password is not an OS sandbox. An agent or process that can invoke raw `op`, inspect another process, replace a trusted executable, or otherwise escape the intended tool surface is outside this boundary.

A stronger guarantee—binding a credential to an exact action or destination without giving arbitrary child processes plaintext—requires a broker/private-executor boundary rather than generic process injection.

If 2password exposes a secret unexpectedly in output, an error, argv, a file, or another process's environment outside the documented execution boundary, that's a vulnerability.

Report vulnerabilities privately at https://github.com/kitlangton/2password/security/advisories/new. Don't open a public issue, and don't include real credentials in your report.
