# Security Policy

## Reporting a Vulnerability

To report a security issue, please use [https://goo.gl/vulnz](https://goo.gl/vulnz) or submit a private report via [GitHub Security Advisories](https://github.com/danicat/go-aida/security/advisories/new). Please **do not** file a public GitHub issue for security vulnerabilities.

We use [https://goo.gl/vulnz](https://goo.gl/vulnz) for our intake, and do coordination and disclosure here on GitHub (including using GitHub Security Advisory). The Google Security Team will respond within 5 working days of your report on g.co/vulnz.

---

## Security Architecture & Operational Posture

AIDA (`go-aida`) is an AI-driven host diagnostic agent that inspects live system telemetry and can propose host commands. To protect the host environment against unintended execution, prompt injection, and cross-origin attacks, AIDA enforces three defense-in-depth boundaries:

### 1. Loopback-by-Default Network Binding & Origin Validation

- **Localhost Binding**: By default, the AIDA HTTP server binds exclusively to `127.0.0.1:8090` (`-addr 127.0.0.1:8090`). Binding to a non-loopback interface (such as `0.0.0.0`) is rejected at startup unless the operator explicitly supplies the `-allow-remote` flag.
- **DNS Rebinding & CSRF Protection**: All mutating API endpoints (`POST /api/chat` and `POST /api/action`) enforce strict `Host` and `Origin` header validation, rejecting cross-origin browser requests when bound to loopback.

### 2. Read-Only `osquery` Telemetry Execution

- **Process-Level Read-Only Flags**: The `run_osquery` tool invokes `osqueryi` directly via `exec.CommandContext` (never through a shell) with mandatory read-only and extension-lockdown flags:
  ```text
  osqueryi --readonly=true --disable_extensions=true --json <sql>
  ```
- **Pre-Execution SQL Gate**: Before invoking `osqueryi`, AIDA validates the SQL string to ensure:
  - Only single-statement queries (`SELECT`, `PRAGMA`, or `WITH`) are permitted; semicolon-chained statements (`;`) are rejected.
  - Dangerous SQLite/osquery meta-commands and functions (such as `ATTACH`, `DETACH`, `LOAD_EXTENSION`, `WRITEFILE`, `READFILE`, `EDIT`, and `FTS3_TOKENIZER`) are blocked.

### 3. Human-in-the-Loop (`runCommand`) Operator Confirmation Gate

- **Mandatory Operator Interrupt (`ctx.Interrupt`)**: Whenever the diagnostic agent invokes the `runCommand` tool, execution immediately halts via Genkit's interrupt mechanism (`ctx.Interrupt`). No host command is executed automatically by the model.
- **Explicit Approval Required**: The paused tool call is surfaced in the Web Cockpit's confirmation modal showing the exact executable, argument array, and reason. The command only runs if the human operator clicks **Approve & Execute** (`approved: true`).
- **No Shell Interpolation**: Approved commands are executed via `exec.CommandContext(ctx, command, args...)` directly as an argument vector without invoking `sh -c` or `cmd /c`, preventing shell metacharacter injection, command chaining, and arbitrary redirection.
