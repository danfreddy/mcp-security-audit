import ast
import json
import logging
import math
import os
import re
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

LOG_FILE = os.path.expanduser("~/.mcp-security-audit/audit.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("mcp-security-audit")

MAX_CALLS_PER_MINUTE = 10
_call_timestamps: list[float] = []

CHECKS = [
    {
        "id": "input_validation",
        "name": "Input Validation",
        "owasp": "#5 Command Injection",
        "description": "Tool functions must validate string parameters with regex, isinstance, or whitelist checks.",
    },
    {
        "id": "output_sanitization",
        "name": "Output Sanitization",
        "owasp": "#10 Context Injection and Over-Sharing",
        "description": "External API responses must be sanitized before returning to the LLM.",
    },
    {
        "id": "rate_limiting",
        "name": "Rate Limiting",
        "owasp": "#2 Privilege Escalation via Scope Creep",
        "description": "Server must implement rate limiting on tool calls.",
    },
    {
        "id": "credential_safety",
        "name": "Credential Safety",
        "owasp": "#1 Token Mismanagement and Secret Exposure",
        "description": "No hardcoded API keys, tokens, or passwords. Use environment variables.",
    },
    {
        "id": "shell_injection",
        "name": "Shell Injection Prevention",
        "owasp": "#5 Command Injection",
        "description": "No os.system(), subprocess with shell=True, eval(), or exec().",
    },
    {
        "id": "error_handling",
        "name": "Error Handling",
        "owasp": "#8 Lack of Audit and Telemetry",
        "description": "No bare except clauses. Exception handlers must not leak internal details.",
    },
    {
        "id": "request_timeout",
        "name": "Request Timeout",
        "owasp": "General Best Practice",
        "description": "All HTTP requests must include a timeout parameter.",
    },
    {
        "id": "logging_presence",
        "name": "Logging",
        "owasp": "#8 Lack of Audit and Telemetry",
        "description": "Server must import and configure the logging module.",
    },
    {
        "id": "write_safety",
        "name": "Write Operation Safety",
        "owasp": "#6 Intent Flow Subversion",
        "description": "Write/send/delete operations need safety guards (confirmation, draft mode).",
    },
    {
        "id": "supply_chain",
        "name": "Supply Chain Safety",
        "owasp": "#4 Supply Chain Attacks",
        "description": "No use of pickle.load, torch.load, marshal.load, or similar unsafe deserialization.",
    },
]

PATH_PATTERN = re.compile(r"^[a-zA-Z0-9_\-/.\\ ]+\.py$")
HIGH_ENTROPY_THRESHOLD = 4.0
MIN_SECRET_LENGTH = 16
SECRET_PREFIXES = ("sk-", "sk_", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-", "AKIA", "eyJ")
SECRET_KEYWORDS = re.compile(
    r"(?i)(password|passwd|secret|api_key|apikey|token|bearer|authorization)",
)

WRITE_PATTERNS = re.compile(
    r"(?i)^.*(send|delete|remove|publish|write|drop|truncate|destroy).*$",
)
WRITE_EXCLUSIONS = re.compile(
    r"(?i)(get_|list_|read_|fetch_|search_|recent_|_posts$|_items$|_results$|_list$)",
)

SAFETY_GUARD_PATTERNS = re.compile(
    r"(?i)(draft|confirm|dry_run|preview|approve|sandbox|simulate|safe)",
)

mcp = FastMCP("mcp-security-audit")


def _rate_limit():
    now = time.time()
    _call_timestamps[:] = [t for t in _call_timestamps if now - t < 60]
    if len(_call_timestamps) >= MAX_CALLS_PER_MINUTE:
        raise RuntimeError(f"Rate limit exceeded: max {MAX_CALLS_PER_MINUTE} calls per minute")
    _call_timestamps.append(now)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _find_tool_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            deco_src = ast.dump(deco)
            if "tool" in deco_src.lower():
                results.append(node)
                break
    return results


def _has_validation_calls(func: ast.FunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("isinstance", "validate", "validator"):
                return True
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr in ("match", "fullmatch", "search", "compile", "validate", "strip", "startswith", "endswith"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in ("re", "pattern", "regex"):
                        return True
                if attr in ("validate", "strip"):
                    return True

        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.In, ast.NotIn)):
                    return True

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id.lower()
            if "validat" in name or "sanitiz" in name or "check" in name:
                return True

    for node in ast.walk(func):
        if isinstance(node, ast.If):
            test_dump = ast.dump(node.test).lower()
            if "isinstance" in test_dump:
                return True
            if any(kw in test_dump for kw in ["pattern", "allowed", "whitelist", "valid"]):
                return True

    return False


def _check_input_validation(tree: ast.Module) -> list[dict]:
    findings = []
    tool_funcs = _find_tool_functions(tree)

    if not tool_funcs:
        findings.append({
            "status": "WARN",
            "line": 0,
            "detail": "No @tool() decorated functions found. Cannot verify input validation.",
        })
        return findings

    has_module_level_validation = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not any(node is tf for tf in tool_funcs):
            name = node.name.lower()
            if "validat" in name or "sanitiz" in name or "check" in name:
                has_module_level_validation = True
                break

    for func in tool_funcs:
        str_params = []
        for arg in func.args.args:
            if arg.annotation:
                ann_src = ast.dump(arg.annotation)
                if "str" in ann_src:
                    str_params.append(arg.arg)

        if not str_params:
            continue

        calls_validation_func = False
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id.lower()
                if "validat" in name or "sanitiz" in name or "check" in name:
                    calls_validation_func = True
                    break

        has_validation = _has_validation_calls(func) or calls_validation_func

        if not has_validation and has_module_level_validation:
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    has_validation = True
                    break

        if not has_validation:
            findings.append({
                "status": "FAIL",
                "line": func.lineno,
                "detail": f"Function '{func.name}' has string parameters {str_params} without visible input validation.",
            })

    if not findings:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Tool functions validate their string parameters.",
        })

    return findings


def _check_output_sanitization(tree: ast.Module, source_lines: list[str]) -> list[dict]:
    findings = []

    has_sanitize_func = False
    has_injection_pattern = False

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and "sanitiz" in node.name.lower():
            has_sanitize_func = True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name_lower = target.id.lower()
                    if "injection" in name_lower or "sanitiz" in name_lower:
                        has_injection_pattern = True

    has_external_calls = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "requests":
                has_external_calls = True
        if isinstance(node, ast.Call):
            call_src = ast.dump(node).lower()
            if "urlopen" in call_src or "httpx" in call_src or "aiohttp" in call_src:
                has_external_calls = True

    if has_external_calls and not has_sanitize_func:
        findings.append({
            "status": "FAIL",
            "line": 0,
            "detail": "External API calls detected but no sanitization function found.",
        })
    elif has_sanitize_func and has_injection_pattern:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Output sanitization function with injection pattern detection found.",
        })
    elif has_sanitize_func:
        findings.append({
            "status": "WARN",
            "line": 0,
            "detail": "Sanitization function exists but no injection pattern matching detected.",
        })
    elif not has_external_calls:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "No external API calls detected. Output sanitization not required.",
        })
    else:
        findings.append({
            "status": "WARN",
            "line": 0,
            "detail": "Could not determine if output sanitization is applied to external data.",
        })

    return findings


def _check_rate_limiting(tree: ast.Module, source_lines: list[str]) -> list[dict]:
    findings = []
    source_text = "\n".join(source_lines).lower()

    rate_limit_indicators = [
        "rate_limit", "ratelimit", "rate limit",
        "calls_per_minute", "max_calls", "throttle",
        "semaphore", "token_bucket", "leaky_bucket",
    ]

    found = any(indicator in source_text for indicator in rate_limit_indicators)

    if found:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Rate limiting mechanism detected.",
        })
    else:
        findings.append({
            "status": "FAIL",
            "line": 0,
            "detail": "No rate limiting detected. MCP servers should limit tool call frequency.",
        })

    return findings


def _check_credential_safety(tree: ast.Module) -> list[dict]:
    findings = []
    uses_env_vars = False
    hardcoded_secrets = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_src = ast.dump(node)
            if "getenv" in call_src or "dotenv" in call_src or "load_dotenv" in call_src:
                uses_env_vars = True

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        val = node.value
        if len(val) < MIN_SECRET_LENGTH:
            continue
        if any(val.startswith(prefix) for prefix in SECRET_PREFIXES):
            hardcoded_secrets.append((getattr(node, "lineno", 0), val[:20] + "..."))
            continue
        is_regex = any(ch in val for ch in ("(?", "|", "\\s", "\\w", "\\d", "+?"))
        is_prose = val.count(" ") >= 3
        is_path = any(c in val for c in ("/", "\\", "~")) and any(val.endswith(ext) for ext in (".py", ".json", ".log", ".txt", ".md", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".sh", ".env"))
        is_format = val.startswith(("http", "/", "#", "%(", "{", "=", "~"))
        if is_regex or is_prose or is_format or is_path:
            continue
        if _shannon_entropy(val) > HIGH_ENTROPY_THRESHOLD:
            if SECRET_KEYWORDS.search(val):
                hardcoded_secrets.append((getattr(node, "lineno", 0), val[:20] + "..."))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_KEYWORDS.search(target.id):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) >= 8 and not val.startswith(("$", "%", "{")):
                            hardcoded_secrets.append((node.lineno, f"{target.id} = '{val[:15]}...'"))

    if hardcoded_secrets:
        for line, preview in hardcoded_secrets:
            findings.append({
                "status": "FAIL",
                "line": line,
                "detail": f"Possible hardcoded secret: {preview}",
            })
    elif uses_env_vars:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Credentials loaded from environment variables. No hardcoded secrets detected.",
        })
    else:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "No hardcoded secrets detected.",
        })

    return findings


def _check_shell_injection(tree: ast.Module) -> list[dict]:
    findings = []
    dangerous_calls = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                if node.func.attr == "system":
                    dangerous_calls.append((getattr(node, "lineno", 0), "os.system()"))

        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                dangerous_calls.append((getattr(node, "lineno", 0), "eval()"))
            elif node.func.id == "exec":
                dangerous_calls.append((getattr(node, "lineno", 0), "exec()"))

        if isinstance(node.func, ast.Attribute) and node.func.attr in ("call", "run", "Popen", "check_output", "check_call"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        dangerous_calls.append((getattr(node, "lineno", 0), f"subprocess.{node.func.attr}(shell=True)"))

    for line, call_name in dangerous_calls:
        findings.append({
            "status": "CRITICAL",
            "line": line,
            "detail": f"Dangerous call: {call_name}. This allows arbitrary code/command execution.",
        })

    if not findings:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "No shell injection vectors (os.system, eval, exec, subprocess shell=True) found.",
        })

    return findings


def _check_error_handling(tree: ast.Module) -> list[dict]:
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue

        if node.type is None:
            has_logging = False
            for child in ast.walk(node):
                child_src = ast.dump(child).lower()
                if "logger" in child_src or "logging" in child_src or "log" in child_src:
                    has_logging = True
                    break
            if not has_logging:
                findings.append({
                    "status": "WARN",
                    "line": node.lineno,
                    "detail": "Bare 'except:' clause without logging. Errors may be silently swallowed.",
                })

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_src = ast.dump(child)
                if "format_exc" in call_src or "print_exc" in call_src:
                    findings.append({
                        "status": "WARN",
                        "line": getattr(child, "lineno", node.lineno),
                        "detail": "Stack trace formatting in error handler. Ensure this is only logged, not returned.",
                    })

    if not findings:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Error handling follows best practices. No bare except clauses or leaked internals.",
        })

    return findings


def _check_request_timeout(tree: ast.Module) -> list[dict]:
    findings = []
    http_methods = {"get", "post", "put", "delete", "patch", "head", "options"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in http_methods:
            continue

        caller_name = ""
        if isinstance(node.func.value, ast.Name):
            caller_name = node.func.value.id
        elif isinstance(node.func.value, ast.Attribute):
            caller_name = ast.dump(node.func.value)

        if "requests" not in caller_name.lower() and "session" not in caller_name.lower() and "client" not in caller_name.lower() and "http" not in caller_name.lower():
            continue

        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)

        if not has_timeout:
            findings.append({
                "status": "FAIL",
                "line": getattr(node, "lineno", 0),
                "detail": f"HTTP call requests.{node.func.attr}() without timeout parameter. Can hang indefinitely.",
            })

    if not findings:
        has_requests = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "requests":
                        has_requests = True
            if isinstance(node, ast.ImportFrom):
                if node.module and "requests" in node.module:
                    has_requests = True

        if has_requests:
            findings.append({
                "status": "PASS",
                "line": 0,
                "detail": "All HTTP requests include timeout parameters.",
            })
        else:
            findings.append({
                "status": "PASS",
                "line": 0,
                "detail": "No HTTP request library usage detected.",
            })

    return findings


def _check_logging_presence(tree: ast.Module) -> list[dict]:
    findings = []
    has_logging_import = False
    has_logger_config = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "logging":
                    has_logging_import = True
        if isinstance(node, ast.ImportFrom):
            if node.module and "logging" in node.module:
                has_logging_import = True

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_src = ast.dump(node)
            if "basicConfig" in call_src or "getLogger" in call_src:
                has_logger_config = True

    if has_logging_import and has_logger_config:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Logging module imported and configured.",
        })
    elif has_logging_import:
        findings.append({
            "status": "WARN",
            "line": 0,
            "detail": "Logging imported but no logger configuration (basicConfig/getLogger) found.",
        })
    else:
        findings.append({
            "status": "FAIL",
            "line": 0,
            "detail": "No logging module usage detected. MCP servers must log all tool calls.",
        })

    return findings


def _check_write_safety(tree: ast.Module) -> list[dict]:
    findings = []
    tool_funcs = _find_tool_functions(tree)

    for func in tool_funcs:
        func_name = func.name.lower()
        if not WRITE_PATTERNS.search(func_name):
            continue
        if WRITE_EXCLUSIONS.search(func_name):
            continue

        has_guard = False
        for arg in func.args.args:
            if SAFETY_GUARD_PATTERNS.search(arg.arg):
                has_guard = True
                break

        if not has_guard:
            defaults_offset = len(func.args.args) - len(func.args.defaults)
            for i, arg in enumerate(func.args.args):
                default_idx = i - defaults_offset
                if default_idx >= 0:
                    default = func.args.defaults[default_idx]
                    if isinstance(default, ast.Constant) and default.value is False:
                        ann = arg.annotation
                        if ann and "bool" in ast.dump(ann).lower():
                            has_guard = True
                            break

        if not has_guard:
            for node in ast.walk(func):
                node_src = ast.dump(node).lower()
                if any(kw in node_src for kw in ["draft", "confirm", "dry_run", "preview", "approve"]):
                    has_guard = True
                    break

        if not has_guard:
            docstring = ast.get_docstring(func) or ""
            if SAFETY_GUARD_PATTERNS.search(docstring.lower()):
                has_guard = True

        if not has_guard:
            findings.append({
                "status": "WARN",
                "line": func.lineno,
                "detail": f"Write operation '{func.name}' has no visible safety guard (draft, confirm, preview).",
            })

    if not findings:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "Write operations have appropriate safety guards or no write tools detected.",
        })

    return findings


def _check_supply_chain(tree: ast.Module) -> list[dict]:
    findings = []
    risky_modules = {"pickle", "cPickle", "marshal", "shelve", "dill", "cloudpickle"}
    risky_loads = {"pickle.load", "pickle.loads", "torch.load", "marshal.load", "marshal.loads", "shelve.open", "dill.load", "dill.loads", "yaml.load"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in risky_modules:
                    findings.append({
                        "status": "WARN",
                        "line": node.lineno,
                        "detail": f"Import of '{alias.name}' detected. This module allows arbitrary code execution during deserialization.",
                    })
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in risky_modules:
                findings.append({
                    "status": "WARN",
                    "line": node.lineno,
                    "detail": f"Import from '{node.module}' detected. This module allows arbitrary code execution during deserialization.",
                })

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                full_call = f"{node.func.value.id}.{node.func.attr}"
                if full_call in risky_loads:
                    findings.append({
                        "status": "CRITICAL",
                        "line": getattr(node, "lineno", 0),
                        "detail": f"Unsafe deserialization: {full_call}(). Allows arbitrary code execution.",
                    })

    if not findings:
        findings.append({
            "status": "PASS",
            "line": 0,
            "detail": "No risky deserialization imports or calls (pickle, marshal, torch.load) detected.",
        })

    return findings


def _compute_verdict(results: dict[str, list[dict]]) -> dict:
    weights = {
        "CRITICAL": 25,
        "FAIL": 10,
        "WARN": 3,
        "PASS": 0,
    }

    total_penalty = 0
    critical_count = 0
    fail_count = 0
    warn_count = 0
    pass_count = 0

    for check_findings in results.values():
        for finding in check_findings:
            status = finding["status"]
            total_penalty += weights.get(status, 0)
            if status == "CRITICAL":
                critical_count += 1
            elif status == "FAIL":
                fail_count += 1
            elif status == "WARN":
                warn_count += 1
            elif status == "PASS":
                pass_count += 1

    if critical_count > 0 or total_penalty >= 50:
        verdict = "INSECURE"
    elif fail_count > 0 or total_penalty >= 20:
        verdict = "NEEDS_ATTENTION"
    else:
        verdict = "SECURE"

    return {
        "verdict": verdict,
        "score_penalty": total_penalty,
        "summary": {
            "critical": critical_count,
            "fail": fail_count,
            "warn": warn_count,
            "pass": pass_count,
        },
    }


def _format_results(file_path: str, results: dict[str, list[dict]], verdict_info: dict) -> str:
    check_lookup = {c["id"]: c for c in CHECKS}
    lines = []
    lines.append("MCP Security Audit Report")
    lines.append("=" * 60)
    lines.append(f"File: {file_path}")
    lines.append(f"Verdict: {verdict_info['verdict']}")
    lines.append(f"Score penalty: {verdict_info['score_penalty']} (0 = perfect)")
    summary = verdict_info["summary"]
    lines.append(f"Summary: {summary['pass']} PASS, {summary['warn']} WARN, {summary['fail']} FAIL, {summary['critical']} CRITICAL")
    lines.append("=" * 60)
    lines.append("")

    status_order = {"CRITICAL": 0, "FAIL": 1, "WARN": 2, "PASS": 3}

    for check_id, check_findings in results.items():
        meta = check_lookup.get(check_id, {})
        check_name = meta.get("name", check_id)
        owasp = meta.get("owasp", "N/A")
        lines.append(f"[{check_name}] (OWASP MCP {owasp})")

        sorted_findings = sorted(check_findings, key=lambda f: status_order.get(f["status"], 99))
        for finding in sorted_findings:
            loc = f" (line {finding['line']})" if finding["line"] > 0 else ""
            lines.append(f"  {finding['status']}{loc}: {finding['detail']}")
        lines.append("")

    lines.append("=" * 60)
    lines.append("Verdict explanation:")
    lines.append("  SECURE         = No critical or failing checks, low warning count.")
    lines.append("  NEEDS_ATTENTION = Some checks failed. Review recommended before deployment.")
    lines.append("  INSECURE       = Critical issues found. Do not deploy without fixing.")
    lines.append("=" * 60)

    return "\n".join(lines)


def _validate_file_path(file_path: str) -> Path:
    if not file_path or not isinstance(file_path, str):
        raise ValueError("file_path must be a non-empty string")

    if not PATH_PATTERN.match(file_path):
        raise ValueError("file_path contains invalid characters")

    resolved = Path(file_path).resolve()

    if resolved.suffix != ".py":
        raise ValueError("Only .py files can be audited")

    if not resolved.exists():
        raise ValueError(f"File not found: {resolved}")

    if not resolved.is_file():
        raise ValueError(f"Path is not a file: {resolved}")

    max_size = 5 * 1024 * 1024
    if resolved.stat().st_size > max_size:
        raise ValueError(f"File too large (max 5 MB): {resolved.stat().st_size} bytes")

    return resolved


@mcp.tool()
def audit_server(file_path: str) -> str:
    """Run a security audit on a Python MCP server file.

    Performs 10 static analysis checks mapped to the OWASP MCP Top 10.
    Returns a detailed report with PASS/WARN/FAIL/CRITICAL per check
    and an overall verdict (SECURE / NEEDS_ATTENTION / INSECURE).

    Args:
        file_path: Absolute path to a .py file to audit.
    """
    _rate_limit()
    logger.info("audit_server called: %s", file_path)

    try:
        resolved = _validate_file_path(file_path)
    except ValueError as e:
        logger.warning("Validation failed for %s: %s", file_path, str(e))
        return f"Validation error: {e}"

    try:
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        logger.warning("Could not read file: %s", file_path)
        return "Error: Could not read the file. Ensure it is a valid UTF-8 Python file."

    try:
        tree = ast.parse(source, filename=str(resolved))
    except SyntaxError as e:
        logger.warning("Syntax error in %s: line %s", file_path, e.lineno)
        return f"Syntax error at line {e.lineno}: {e.msg}. Cannot audit a file with syntax errors."

    source_lines = source.splitlines()

    results: dict[str, list[dict]] = {}
    results["input_validation"] = _check_input_validation(tree)
    results["output_sanitization"] = _check_output_sanitization(tree, source_lines)
    results["rate_limiting"] = _check_rate_limiting(tree, source_lines)
    results["credential_safety"] = _check_credential_safety(tree)
    results["shell_injection"] = _check_shell_injection(tree)
    results["error_handling"] = _check_error_handling(tree)
    results["request_timeout"] = _check_request_timeout(tree)
    results["logging_presence"] = _check_logging_presence(tree)
    results["write_safety"] = _check_write_safety(tree)
    results["supply_chain"] = _check_supply_chain(tree)

    verdict_info = _compute_verdict(results)
    report = _format_results(str(resolved), results, verdict_info)

    logger.info("audit_server completed: %s -> %s", file_path, verdict_info["verdict"])
    return report


@mcp.tool()
def list_checks() -> str:
    """List all security checks performed by the audit.

    Returns a formatted list of all 10 checks with their names,
    OWASP MCP Top 10 mapping, and descriptions.
    """
    _rate_limit()
    logger.info("list_checks called")

    lines = []
    lines.append("MCP Security Audit - Checks")
    lines.append("=" * 50)
    lines.append("")

    for i, check in enumerate(CHECKS, 1):
        lines.append(f"{i:2d}. {check['name']}")
        lines.append(f"    OWASP MCP: {check['owasp']}")
        lines.append(f"    {check['description']}")
        lines.append("")

    lines.append("=" * 50)
    lines.append("Each check returns: PASS | WARN | FAIL | CRITICAL")
    lines.append("Overall verdict: SECURE | NEEDS_ATTENTION | INSECURE")

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
