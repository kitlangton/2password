# Security

2password exists to keep secrets out of agent-visible surfaces by default.

Discovery, metadata, receipts, errors, and write paths must never expose secret values in argv, stdout, stderr, or diagnostics. Plaintext is allowed to cross that boundary only through an explicit consumption path:

- `read` writes one secret to stdout.
- `env resolve` materializes secrets into the requested file.
- `run` and `env run` inject secrets into the selected child process environment.

For `run` and `env run`, the child process is inside the trust boundary. 2password does not print the injected values itself, but a child can print, persist, or transmit any credential it receives. This is secret injection, not a sandbox around an untrusted command.

Unexpected exposure outside those explicit paths — including a secret in an error, diagnostic, argument, receipt, metadata response, or unrelated process environment — is a vulnerability.

Report vulnerabilities privately at https://github.com/kitlangton/2password/security/advisories/new. Don't open a public issue, and don't include real credentials in your report.
