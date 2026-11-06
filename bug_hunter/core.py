"""Data model, fingerprints and constants."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Any

VERSION = "4.0.2"
MAX_DEFAULT_BYTES = 2_000_000
DEFAULT_EXCLUDES = (".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build")
SEVERITY = {"ERROR": 3, "WARNING": 2, "NOTE": 1}

# Preserve the original 18 root-cause labels. Scores are heuristics, NOT probabilities.

@dataclass(frozen=True)
class Finding:
    rule_id: str
    file: str
    line: int
    column: int
    message: str
    severity: str
    root_cause: str
    cwe: str | None
    recommendation: str
    fingerprint: str
    confidence: str = "heuristic"

    def as_json(self) -> dict[str, Any]:
        data = asdict(self)
        data.update({"pattern": self.rule_id, "risk": {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}[self.severity], "description": self.message})
        return data

def _fingerprint(rule: str, path: str, line: int, col: int, message: str) -> str:
    # Location-based fingerprint, used only for operational diagnostics (parse/IO/limit).
    return hashlib.sha256(f"{rule}\0{path}\0{line}\0{col}\0{message}".encode()).hexdigest()[:24]


def _content_fingerprint(rule: str, path: str, snippet: str, occurrence: int) -> str:
    # Content-based: stable across line shifts, unique per rule + code line + occurrence.
    normalized = " ".join(snippet.split())
    return hashlib.sha256(f"{rule}\0{path}\0{normalized}\0{occurrence}".encode()).hexdigest()[:24]

def _limit_diagnostic(path: str, exc: BaseException) -> Finding:
    message = f"Source too deeply nested to analyze ({type(exc).__name__})"
    return Finding("BH_PARSE", path, 1, 1, message, "ERROR", "UNKNOWN_ROOT_CAUSE", None,
                   "Simplify nesting before scanning", _fingerprint("BH_PARSE", path, 1, 1, message), "certain")
