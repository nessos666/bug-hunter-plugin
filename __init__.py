"""bug_hunter als Hermes-Plugin — /bugscan und das Tool ``bug_scan``.

Offline, deterministisch, ohne LLM. Der Scanner ist im Plugin mitgeliefert
(Verzeichnis ``bug_hunter/``), es muss also nichts per pip installiert werden.

Read-only: Quellcode wird mit ``ast`` geparst, nie importiert und nie ausgeführt.
Keine Netzwerkzugriffe, keine Schreibvorgänge, keine Telemetrie.

Befunde sind Hinweise für ein Review, kein Urteil: die Prüfungen sind heuristisch,
die Präzision ist nicht kalibriert, und BH011 schlägt bewusst breit an.
"""
from __future__ import annotations

import json
import os
import sys

# Der mitgelieferte Scanner liegt neben dieser Datei.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from bug_hunter import scan_path, to_sarif  # noqa: E402
from bug_hunter.rules import RULES  # noqa: E402

MAX_FILES = 5000
MAX_BYTES = 2_000_000
MAX_REPORTED = 40
SEVERITY_ORDER = {"ERROR": 3, "WARNING": 2, "NOTE": 1}

DISCLAIMER = (
    "Heuristik, kein Beweis: 14 AST-Regeln, Präzision nicht kalibriert. "
    "Kein Befund heißt nicht 'kein Fehler'."
)


# --------------------------------------------------------------------------- Kern

def _scan(path: str, severity: str | None = None, max_files: int = MAX_FILES) -> list:
    findings = scan_path(path, max_files=max_files, max_bytes=MAX_BYTES)
    if severity:
        floor = SEVERITY_ORDER.get(str(severity).upper(), 0)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= floor]
    return findings


def _counts(findings: list) -> dict:
    counts = {"ERROR": 0, "WARNING": 0, "NOTE": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _text_report(path: str, findings: list) -> str:
    c = _counts(findings)
    lines = [
        f"bug_hunter — {path}",
        f"{len(findings)} Befund(e): {c['ERROR']} ERROR · {c['WARNING']} WARNING · {c['NOTE']} NOTE",
    ]
    if findings:
        lines.append("")
        for f in findings[:MAX_REPORTED]:
            cwe = f" {f.cwe}" if f.cwe else ""
            lines.append(f"{f.file}:{f.line}:{f.column}  {f.severity:<7} {f.rule_id}{cwe}  {f.message}")
        if len(findings) > MAX_REPORTED:
            lines.append(f"… {len(findings) - MAX_REPORTED} weitere (Tool bug_scan mit format=json für alle)")
    else:
        lines.append("Keine der Regeln hat angesprochen.")
    lines.append("")
    lines.append(DISCLAIMER)
    return "\n".join(lines)


def _resolve(raw: str) -> str | None:
    """Pfad auflösen; None, wenn er nicht existiert."""
    ziel = (raw or "").strip().strip('"').strip("'")
    if not ziel:
        return None
    ziel = os.path.expanduser(ziel)
    return ziel if os.path.exists(ziel) else None


# ----------------------------------------------------------------- Werkzeug

BUG_SCAN_SCHEMA = {
    "name": "bug_scan",
    "description": (
        "Scan Python source offline for 14 classes of defects (unsafe eval/exec, pickle, "
        "unsafe YAML loaders, os.system/popen, shell=True, bare except, swallowed exceptions, "
        "open() without with, subprocess without timeout, '== None', mutable defaults, compile()). "
        "Each finding carries a rule id, CWE id where applicable, severity, root cause and a "
        "content fingerprint. Deterministic, no network, no LLM, read-only (ast only). "
        "Heuristic: findings are review input, not proof; no finding does not mean no bug."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "File or directory to scan (absolute, or ~-relative).",
            },
            "format": {
                "type": "string",
                "enum": ["text", "json", "sarif"],
                "description": "text (default) = readable list, json = full findings, sarif = SARIF 2.1.0.",
            },
            "severity": {
                "type": "string",
                "enum": ["ERROR", "WARNING", "NOTE"],
                "description": "Only report findings at or above this severity.",
            },
            "max_files": {
                "type": "integer",
                "description": f"Upper bound on scanned files (default {MAX_FILES}).",
            },
        },
        "required": ["path"],
    },
}


def _tool_bug_scan(args, **kwargs):
    """Tool-Handler: bekommt ein dict, gibt einen String zurück."""
    args = args or {}
    raw = str(args.get("path") or "")
    path = _resolve(raw)
    if path is None:
        return f"Fehler: Pfad fehlt oder existiert nicht: {raw!r}"

    fmt = str(args.get("format") or "text").lower()
    severity = args.get("severity")
    try:
        max_files = int(args.get("max_files") or MAX_FILES)
    except (TypeError, ValueError):
        max_files = MAX_FILES

    findings = _scan(path, severity, max_files)

    if fmt == "json":
        return json.dumps(
            {
                "path": path,
                "count": len(findings),
                "summary": _counts(findings),
                "disclaimer": DISCLAIMER,
                "findings": [f.as_json() for f in findings],
            },
            ensure_ascii=False,
            indent=2,
        )
    if fmt == "sarif":
        return json.dumps(to_sarif(findings, base=path if os.path.isdir(path) else "."), ensure_ascii=False)
    return _text_report(path, findings)


# ------------------------------------------------------------- Slash-Commands

def _cmd_bugscan(raw_args: str = "") -> dict:
    """``/bugscan <pfad>`` — kurzer Textbericht. Genau ein Parameter."""
    ziel = (raw_args or "").strip() or "."
    path = _resolve(ziel)
    if path is None:
        versucht = os.path.abspath(os.path.expanduser(ziel.strip().strip('"')))
        return {
            "status": "error",
            "message": (
                f"Pfad nicht gefunden: {ziel}\n"
                f"gesucht wurde: {versucht}\n"
                f"Nutzung: /bugscan <datei-oder-ordner>  (ohne Angabe: aktueller Ordner)"
            ),
        }
    findings = _scan(path)
    return {"status": "ok", "message": _text_report(path, findings)}


def _cmd_bugrules(raw_args: str = "") -> dict:
    """``/bugrules`` — die Regeltabelle. Genau ein Parameter."""
    lines = [f"bug_hunter — {len(RULES)} Regeln", ""]
    for rule_id in sorted(RULES):
        root_cause, cwe, severity, description, _fix = RULES[rule_id]
        cwe_part = f" {cwe}" if cwe else ""
        lines.append(f"{rule_id}  {severity:<7} {root_cause:<22}{cwe_part}  {description}")
    lines += ["", "Operativ (immer ERROR, Exit 2): BH_IO · BH_PARSE · BH_LIMIT · BH_SKIP", "", DISCLAIMER]
    return {"status": "ok", "message": "\n".join(lines)}


# ------------------------------------------------------------------ Register

def register(ctx) -> None:
    ctx.register_tool(
        name="bug_scan",
        toolset="bug-hunter",
        schema=BUG_SCAN_SCHEMA,
        handler=_tool_bug_scan,
        description="Offline, deterministischer Python-Defekt-Scan (14 Regeln, CWE, SARIF).",
        emoji="🔍",
    )
    ctx.register_command(
        "bugscan",
        handler=_cmd_bugscan,
        description="Python-Code offline auf Defekte scannen (14 Regeln, CWE-IDs).",
        args_hint="<datei-oder-ordner>",
    )
    ctx.register_command(
        "bugrules",
        handler=_cmd_bugrules,
        description="Regeltabelle des bug_hunter-Scanners anzeigen.",
        args_hint="",
    )
