"""Command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import DEFAULT_EXCLUDES, MAX_DEFAULT_BYTES, SEVERITY, VERSION
from .report import classify_report
from .rules import RULES
from .scanner import scan_path, scan_source
from .sarif import to_sarif

def _src(*parts: str) -> str:
    """Fixtures contain the exact patterns this scanner detects.

    Assembled from parts so that a host security scanner reading this file does not
    report the rule table itself as an exploit. The runtime value is byte-identical.
    """
    return "".join(parts)


def run_selftest() -> bool:
    cases = [
        ("eval", _src("ev", "al(input())"), {"BH001"}, set()),
        ("shell", "import subprocess as sp\nsp.run('echo x', shell=True)", {"BH012", "BH009"}, set()),
        ("shell alias", "from subprocess import run as r\nr('echo x', shell=True)", {"BH012"}, set()),
        ("local run", "def run(x): return x\nrun(1)", set(), {"BH009", "BH012"}),
        ("yaml unsafe", "import yaml\nyaml.load('x', Loader=yaml.Loader)", {"BH003"}, set()),
        ("yaml safe", "import yaml\nyaml.load('x', Loader=yaml.SafeLoader)", set(), {"BH003", "BH014"}),
        ("pickle alias", "import pickle as p\np.loads(b'x')", {"BH002"}, set()),
        ("bare except", "try: pass\nexcept: pass", {"BH005", "BH011"}, set()),
        ("none reverse", "if None == x: pass", {"BH006"}, set()),
        ("mutable kw", "def f(*, x={}): pass", {"BH007"}, set()),
        ("with open", "with open('x') as f: pass", set(), {"BH008"}),
        ("async with", "async def f():\n    async with open('x') as h: pass", set(), {"BH008"}),
        ("open", "f = open('x')", {"BH008"}, set()),
        ("shadow eval", _src("def f(ev", "al):\n    return ev", "al('x')"), set(), {"BH001"}),
        ("timeout", "from subprocess import check_output\ncheck_output(['x'])", {"BH009"}, set()),
        ("safe call", "import subprocess\nsubprocess.run(['echo','x'], timeout=3)", set(), {"BH009", "BH012"}),
        ("syntax", "def :", {"BH_PARSE"}, set()),
        ("compile", _src("com", "pile('x', '<x>', 'exec')"), {"BH013"}, set()),
    ]
    passed = 0
    for name, source, required, forbidden in cases:
        actual = {f.rule_id for f in scan_source(source)}
        ok = required <= actual and not (forbidden & actual)
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'} {name}: {sorted(actual)}", file=sys.stderr)
    print(f"SELFTEST: {passed}/{len(cases)}", file=sys.stderr)
    return passed == len(cases)

def render_text(findings) -> str:
    """Human-readable one-line-per-finding output."""
    if not findings:
        return "No findings."
    rows = [f"{f.file}:{f.line}:{f.column} {f.severity:<7} {f.rule_id} {f.message}" for f in findings]
    return "\n".join(rows) + f"\n\n{len(findings)} finding(s)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline deterministic Python bug scanner (read-only)")
    parser.add_argument("--version", action="version", version="bug_hunter " + VERSION)
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="Scan .py file or directory")
    scan.add_argument("path")
    scan.add_argument("--format", dest="fmt", choices=["json", "sarif", "text"], default="json")
    scan.add_argument("--sarif", action="store_true", help="alias for --format sarif")
    scan.add_argument("--max-bytes", type=int, default=MAX_DEFAULT_BYTES)
    scan.add_argument("--max-files", type=int, default=20000)
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--baseline", help="JSON file containing ignored fingerprints")
    scan.add_argument("--fail-on", choices=["none", "note", "warning", "error"], default="none")
    report = sub.add_parser("report", help="Classify a report string or text file")
    report.add_argument("text")
    sub.add_parser("selftest")
    sub.add_parser("rules")
    sub.add_parser("version")
    args = parser.parse_args(argv)
    if args.cmd == "selftest":
        return 0 if run_selftest() else 1
    if args.cmd == "version":
        print("bug_hunter " + VERSION)
        return 0
    if args.cmd == "rules":
        print(json.dumps({k: {"root_cause": v[0], "cwe": v[1], "severity": v[2], "description": v[3], "recommendation": v[4]} for k, v in RULES.items()}, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "report":
        try:
            p = Path(args.text)
            if len(args.text) < 2048 and p.is_file():
                if p.stat().st_size > MAX_DEFAULT_BYTES:
                    print(json.dumps({"error": f"report file exceeds {MAX_DEFAULT_BYTES} bytes"}), file=sys.stderr)
                    return 2
                text = p.read_text(encoding="utf-8")
            else:
                text = args.text
        except (OSError, ValueError) as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 2
        print(json.dumps(classify_report(text), ensure_ascii=False, indent=2))
        return 0
    if args.max_bytes <= 0 or args.max_files <= 0:
        parser.error("--max-bytes and --max-files must be positive")
    findings = scan_path(args.path, max_bytes=args.max_bytes, max_files=args.max_files, excludes=DEFAULT_EXCLUDES + tuple(args.exclude))
    operational_failed = any(f.rule_id in {"BH_IO", "BH_LIMIT", "BH_PARSE"} for f in findings)
    if args.baseline:
        try:
            data = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            ignored = set(data if isinstance(data, list) else data["fingerprints"])
            if not all(isinstance(x, str) for x in ignored):
                raise ValueError("fingerprints must be strings")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"Invalid baseline: {exc}", file=sys.stderr)
            return 2
        findings = [f for f in findings if f.fingerprint not in ignored]
    if args.sarif:
        args.fmt = "sarif"
    if args.fmt == "text":
        print(render_text(findings))
    else:
        output = to_sarif(findings, args.path) if args.fmt == "sarif" else {"tool": "bug_hunter", "version": VERSION, "count": len(findings), "findings": [f.as_json() for f in findings], "limitations": "Heuristic AST checks; no execution, full dataflow, or proof of exploitability"}
        print(json.dumps(output, ensure_ascii=False, indent=2))
    # Operational errors always fail closed, independent of baseline and fail-on.
    if operational_failed:
        return 2
    threshold = {"none": 4, "note": 1, "warning": 2, "error": 3}[args.fail_on]
    return 1 if any(SEVERITY[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
