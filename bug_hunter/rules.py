"""Rule table and root-cause classes (heuristics, not probabilities)."""
from __future__ import annotations

from typing import Any

ROOT_CAUSE_CLASSES: dict[str, dict[str, Any]] = {
    "MISSING_GUARD": {"keywords": ["none", "null", "nil", "undefined", "not found", "has no attribute"], "bug_types": ["NullPointer", "KeyError", "IndexError"], "description": "Missing guard before access", "fix_pattern": "Validate object/index before access"},
    "MISSING_VALIDATION": {"keywords": ["input", "user input", "sanitize", "validate", "invalid", "untrusted"], "bug_types": ["ValueError", "SecurityRisk"], "description": "Missing input validation", "fix_pattern": "Validate untrusted input at boundary"},
    "WRONG_TYPE_CONVERSION": {"keywords": ["cannot convert", "unsupported operand", "int(", "str(", "cast", "concatenate", "expected.*got", "typeerror"], "bug_types": ["TypeError", "ValueError"], "description": "Type mismatch", "fix_pattern": "Check expected and actual types"},
    "BAD_IMPORT_PATH": {"keywords": ["cannot import", "unresolved", "circular import", "importerror"], "bug_types": ["ImportError", "ModuleNotFoundError"], "description": "Import path issue", "fix_pattern": "Verify module and import path"},
    "MISSING_DEPENDENCY": {"keywords": ["package", "library", "dependency", "install", "pip", "no module named", "modulenotfound"], "bug_types": ["ImportError", "ModuleNotFoundError"], "description": "Dependency unavailable", "fix_pattern": "Verify environment and declared dependencies"},
    "API_VERSION_MISMATCH": {"keywords": ["deprecated", "removed", "version", "upgrade", "migrated", "no longer supported"], "bug_types": ["ImportError", "TypeError", "AttributeError"], "description": "API version mismatch", "fix_pattern": "Compare installed and required API versions"},
    "BROKEN_CONFIG": {"keywords": ["config", "yaml", "json", "toml", "env", "settings", ".conf"], "bug_types": ["KeyError", "FileNotFoundError"], "description": "Configuration issue", "fix_pattern": "Validate configuration and defaults"},
    "BAD_STATE_TRANSITION": {"keywords": ["state", "transition", "invalid state", "not in state"], "bug_types": ["RuntimeError"], "description": "Invalid state transition", "fix_pattern": "Validate allowed state transitions"},
    "RACE_CONDITION": {"keywords": ["race", "concurrent", "thread", "simultaneous", "data race"], "bug_types": ["RaceCondition"], "description": "Possible concurrency race", "fix_pattern": "Inspect shared mutable state and synchronization"},
    "TIMEOUT": {"keywords": ["timeout", "timed out", "too long", "deadline", "slow"], "bug_types": ["TimeoutError"], "description": "Operation exceeded time limit", "fix_pattern": "Bound operations and handle timeout"},
    "DEADLOCK": {"keywords": ["deadlock", "lock wait", "acquired", "transaction", "mutex"], "bug_types": ["Deadlock"], "description": "Possible deadlock", "fix_pattern": "Review lock acquisition order"},
    "RESOURCE_LEAK": {"keywords": ["leak", "exhausted", "pool", "connection", "memory", "file handle"], "bug_types": ["MemoryError"], "description": "Resource leak", "fix_pattern": "Use context managers or finally cleanup"},
    "PERMISSION_DENIED": {"keywords": ["permission", "denied", "access", "cannot write", "read-only"], "bug_types": ["PermissionError"], "description": "Permission denied", "fix_pattern": "Review access rights and target path"},
    "BAD_ERROR_HANDLING": {"keywords": ["exception", "catch", "error", "swallow", "bare except"], "bug_types": ["UnhandledError"], "description": "Error handling issue", "fix_pattern": "Catch specific errors and preserve diagnostics"},
    "UNSAFE_EVAL": {"keywords": ["eval", "exec", "compile", "__import__", "pickle", "marshal", "deserializ", "code execution"], "bug_types": ["SecurityRisk"], "description": "Potential unsafe dynamic execution", "fix_pattern": "Use safe parsers and validate trust boundaries"},
    "UNSAFE_SHELL": {"keywords": ["os.system", "subprocess", "shell=true", "popen", "rm -rf"], "bug_types": ["SecurityRisk"], "description": "Potential shell execution risk", "fix_pattern": "Prefer argument arrays and shell=False"},
    "DATA_SHAPE_MISMATCH": {"keywords": ["shape", "dimension", "columns", "rows", "schema", "expected"], "bug_types": ["ValueError", "TypeError", "KeyError"], "description": "Data shape mismatch", "fix_pattern": "Validate input schema"},
    "UNKNOWN_ROOT_CAUSE": {"keywords": [], "bug_types": ["*"], "description": "Insufficient evidence", "fix_pattern": "Collect traceback and reproduction steps"},
}

RULES: dict[str, tuple[str, str | None, str, str, str]] = {
    # rule -> root cause, CWE (only where applicable), severity, description, remediation
    "BH001": ("UNSAFE_EVAL", "CWE-95", "WARNING", "Dynamic eval/exec call", "Avoid dynamic execution of untrusted input"),
    "BH002": ("UNSAFE_EVAL", "CWE-502", "ERROR", "Unsafe deserialization via pickle/marshal", "Do not deserialize untrusted bytes"),
    "BH003": ("UNSAFE_EVAL", "CWE-502", "ERROR", "Potentially unsafe YAML loader", "Use yaml.safe_load or SafeLoader"),
    "BH004": ("UNSAFE_SHELL", "CWE-78", "WARNING", "Shell command execution; review input trust", "Prefer shell=False with an argument list"),
    "BH005": ("BAD_ERROR_HANDLING", "CWE-703", "WARNING", "Bare except catches BaseException", "Catch specific exceptions"),
    "BH006": ("MISSING_GUARD", None, "NOTE", "Comparison to None using == or !=", "Use is None or is not None"),
    "BH007": ("DATA_SHAPE_MISMATCH", None, "WARNING", "Mutable default argument", "Use None and initialize inside the function"),
    "BH008": ("RESOURCE_LEAK", None, "NOTE", "open() outside a context manager", "Use with open(...) where possible"),
    "BH009": ("TIMEOUT", "CWE-400", "NOTE", "subprocess call without explicit timeout", "Specify a bounded timeout where appropriate"),
    "BH010": ("UNSAFE_EVAL", "CWE-502", "ERROR", "Unsafe yaml.unsafe_load", "Use yaml.safe_load"),
    "BH011": ("BAD_ERROR_HANDLING", None, "WARNING", "Exception handler silently discards exception", "Log or handle the exception explicitly"),
    "BH012": ("UNSAFE_SHELL", "CWE-78", "WARNING", "subprocess shell=True", "Prefer shell=False and avoid untrusted shell input"),
    "BH013": ("UNSAFE_EVAL", "CWE-95", "WARNING", "Dynamic compile() call", "Avoid compiling untrusted code"),
    "BH014": ("UNSAFE_EVAL", "CWE-502", "ERROR", "Unsafe yaml.load without a safe Loader", "Use yaml.safe_load or Loader=yaml.SafeLoader"),
    "BH_SKIP": ("UNKNOWN_ROOT_CAUSE", None, "NOTE", "Symlinked .py skipped; not scanned", "Enable follow_symlinks to include it"),
}
