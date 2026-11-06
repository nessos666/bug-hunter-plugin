"""bug_hunter - offline, deterministic, LLM-free Python bug scanner."""
from .core import (DEFAULT_EXCLUDES, MAX_DEFAULT_BYTES, SEVERITY, VERSION,
                   Finding)
from .report import classify_report
from .rules import RULES, ROOT_CAUSE_CLASSES
from .scanner import Scanner, scan_file, scan_path, scan_source
from .sarif import _coerce_finding, to_sarif

__version__ = VERSION

from .cli import main, run_selftest  # noqa: E402  (after version so cli can read it)

__all__ = [
    "__version__", "VERSION", "DEFAULT_EXCLUDES", "MAX_DEFAULT_BYTES", "SEVERITY",
    "Finding", "RULES", "ROOT_CAUSE_CLASSES", "classify_report", "Scanner",
    "scan_source", "scan_file", "scan_path", "to_sarif", "main", "run_selftest",
]