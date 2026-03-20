# MCP Security Audit

Static security analyzer for Python MCP servers, mapped to the OWASP MCP Top 10.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![MCP](https://img.shields.io/badge/MCP-compatible-purple)

## What it does

Point it at any Python MCP server file and get a security report. The analyzer parses the source code using Python's `ast` module (no execution) and checks for 10 categories of security issues. Each check maps to a specific OWASP MCP Top 10 item.

Two tools:
- **`audit_server`** - Full security audit of a `.py` file
- **`list_checks`** - List all checks with descriptions

## OWASP MCP Top 10 Mapping

| # | Check | OWASP MCP Top 10 | Severity |
|---|-------|-------------------|----------|
| 1 | Input Validation | #5 Command Injection | FAIL |
| 2 | Output Sanitization | #10 Context Injection and Over-Sharing | FAIL |
| 3 | Rate Limiting | #2 Privilege Escalation via Scope Creep | FAIL |
| 4 | Credential Safety | #1 Token Mismanagement and Secret Exposure | FAIL |
| 5 | Shell Injection Prevention | #5 Command Injection | CRITICAL |
| 6 | Error Handling | #8 Lack of Audit and Telemetry | WARN |
| 7 | Request Timeout | General Best Practice | FAIL |
| 8 | Logging | #8 Lack of Audit and Telemetry | FAIL |
| 9 | Write Operation Safety | #6 Intent Flow Subversion | WARN |
| 10 | Supply Chain Safety | #4 Supply Chain Attacks | CRITICAL |

## Installation

```bash
pip install mcp-security-audit
```

Or run directly with uvx:

```bash
uvx mcp-security-audit
```

From source:

```bash
git clone https://github.com/dangottwald/mcp-security-audit.git
cd mcp-security-audit
pip install -e .
```

## Usage with Claude Code

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "uvx",
      "args": ["mcp-security-audit"]
    }
  }
}
```

Or if installed locally:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "python",
      "args": ["/path/to/mcp-security-audit/server.py"]
    }
  }
}
```

Then ask Claude: *"Audit the security of my MCP server at /path/to/server.py"*

## Example Output

```
MCP Security Audit Report
============================================================
File: /home/user/my-mcp-server/server.py
Verdict: NEEDS_ATTENTION
Score penalty: 23 (0 = perfect)
Summary: 7 PASS, 1 WARN, 2 FAIL, 0 CRITICAL
============================================================

[Input Validation] (OWASP MCP #5 Command Injection)
  PASS: Tool functions validate their string parameters.

[Output Sanitization] (OWASP MCP #10 Context Injection and Over-Sharing)
  FAIL: External API calls detected but no sanitization function found.

[Rate Limiting] (OWASP MCP #2 Privilege Escalation via Scope Creep)
  PASS: Rate limiting mechanism detected.

[Credential Safety] (OWASP MCP #1 Token Mismanagement and Secret Exposure)
  PASS: Credentials loaded from environment variables. No hardcoded secrets detected.

[Shell Injection Prevention] (OWASP MCP #5 Command Injection)
  PASS: No shell injection vectors found.

[Error Handling] (OWASP MCP #8 Lack of Audit and Telemetry)
  WARN (line 45): Bare 'except:' clause without logging.

[Request Timeout] (OWASP MCP General Best Practice)
  FAIL (line 62): HTTP call requests.get() without timeout parameter.

[Logging] (OWASP MCP #8 Lack of Audit and Telemetry)
  PASS: Logging module imported and configured.

[Write Operation Safety] (OWASP MCP #6 Intent Flow Subversion)
  PASS: Write operations have appropriate safety guards.

[Supply Chain Safety] (OWASP MCP #4 Supply Chain Attacks)
  PASS: No risky deserialization imports or calls detected.

============================================================
Verdict explanation:
  SECURE         = No critical or failing checks, low warning count.
  NEEDS_ATTENTION = Some checks failed. Review recommended before deployment.
  INSECURE       = Critical issues found. Do not deploy without fixing.
============================================================
```

## Checks

### 1. Input Validation
Verifies that `@tool()` functions validate their string parameters using regex, `isinstance`, or whitelist checks. Unvalidated string inputs are a direct path to injection attacks.

### 2. Output Sanitization
Checks for a sanitization function that filters injection patterns and invisible Unicode characters from external API responses before they reach the LLM. Without this, a malicious API response can hijack the agent.

### 3. Rate Limiting
Detects rate limiting mechanisms (timestamp tracking, semaphores, token buckets). Without rate limits, a compromised or misbehaving client can abuse your server.

### 4. Credential Safety
Uses Shannon entropy analysis and prefix matching to detect hardcoded API keys, tokens, and passwords. Verifies credentials come from environment variables or dotenv.

### 5. Shell Injection Prevention
Flags `os.system()`, `subprocess` with `shell=True`, `eval()`, and `exec()` as CRITICAL. These allow arbitrary code execution and should never appear in an MCP server.

### 6. Error Handling
Flags bare `except:` clauses without logging (errors get silently swallowed) and exception handlers that return stack traces or internal paths to clients.

### 7. Request Timeout
Checks every `requests.get/post/put/delete` call for a `timeout` parameter. Missing timeouts can hang your server indefinitely.

### 8. Logging
Verifies the `logging` module is imported and configured with `basicConfig` or `getLogger`. MCP servers must maintain an audit trail of all tool calls.

### 9. Write Operation Safety
Detects tool functions that perform write/send/delete operations and checks for safety guards (draft mode, confirmation, dry run). Prevents the confused deputy problem.

### 10. Supply Chain Safety
Flags imports of `pickle`, `marshal`, `shelve`, `dill` and calls to `pickle.load()`, `torch.load()`, `marshal.load()`. These allow arbitrary code execution during deserialization.

## Verdicts

| Verdict | Condition | Action |
|---------|-----------|--------|
| **SECURE** | No CRITICAL or FAIL findings, penalty < 20 | Ready for deployment |
| **NEEDS_ATTENTION** | Some FAIL findings, penalty 20-49 | Review and fix before deployment |
| **INSECURE** | Any CRITICAL finding or penalty >= 50 | Do not deploy. Fix immediately |

Scoring: CRITICAL = 25 points, FAIL = 10 points, WARN = 3 points, PASS = 0 points.

## Self-audit

This server practices what it preaches. Run it against itself:

```
audit_server("/path/to/mcp-security-audit/server.py")
```

Expected result: **SECURE** (all 10 checks pass).

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Add your check following the existing pattern (AST-based, no code execution)
4. Ensure the server still passes its own audit
5. Submit a pull request

Adding a new check:
- Add an entry to the `CHECKS` list with id, name, OWASP mapping, and description
- Implement `_check_your_check(tree, source_lines)` returning `list[dict]` with status/line/detail
- Wire it into `audit_server()` results dict
- Update this README

## License

MIT License. See [LICENSE](LICENSE).

## Author

Daniel Gottwald
