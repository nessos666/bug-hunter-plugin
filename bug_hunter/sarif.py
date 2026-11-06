"""SARIF 2.1.0 output."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .core import SEVERITY, VERSION, Finding
from .rules import RULES

def to_sarif(findings: list[Finding] | list[dict[str, Any]], base: str = ".") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for item in findings:
        f = item if isinstance(item, Finding) else _coerce_finding(item)
        if f.rule_id not in rules:
            rules[f.rule_id] = {"id": f.rule_id, "shortDescription": {"text": RULES[f.rule_id][3] if f.rule_id in RULES else f.message}, "help": {"text": f.recommendation}, "properties": {"rootCause": f.root_cause, **({"cwe": f.cwe} if f.cwe else {})}}
        try:
            relative_uri = Path(f.file).resolve().relative_to(Path(base).resolve()).as_posix()
            artifact_location = {"uri": relative_uri, "uriBaseId": "%SRCROOT%"}
        except (ValueError, OSError):
            artifact_location = {"uri": Path(f.file).as_posix()}
        results.append({"ruleId": f.rule_id, "level": {"ERROR": "error", "WARNING": "warning", "NOTE": "note"}[f.severity], "message": {"text": f.message}, "partialFingerprints": {"primaryLocationLineHash": f.fingerprint}, "locations": [{"physicalLocation": {"artifactLocation": artifact_location, "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column)}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "bug_hunter", "version": VERSION, "informationUri": "https://sarifweb.azurewebsites.net/", "rules": [rules[k] for k in sorted(rules)]}}, "results": results}]}

def _coerce_finding(data: dict[str, Any]) -> Finding:
    if not isinstance(data, dict) or "rule_id" not in data:
        raise ValueError("Expected a v3 Finding dictionary")
    missing = sorted(set(Finding.__dataclass_fields__) - {"confidence"} - set(data))
    if missing:
        raise ValueError("Missing required Finding fields: " + ", ".join(missing))
    if data.get("severity") not in SEVERITY:
        raise ValueError("Invalid severity: %r" % (data.get("severity"),))
    return Finding(**{k: data[k] for k in Finding.__dataclass_fields__ if k in data})
