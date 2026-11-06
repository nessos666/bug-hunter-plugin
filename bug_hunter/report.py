"""Heuristic classification of bug reports into root-cause classes."""
from __future__ import annotations

import re
from typing import Any

from .rules import ROOT_CAUSE_CLASSES

def _keyword_pattern(keyword: str) -> str:
    """Word-boundary pattern so 'int(' does not match 'print(' and 'none' not 'nonempty'."""
    pattern = re.escape(keyword)
    if keyword[:1].isalnum():
        pattern = r"\b" + pattern
    if keyword[-1:].isalnum():
        pattern = pattern + r"\b"
    return pattern

def classify_report(text: str) -> dict[str, Any]:
    """Heuristic ranking, not a verified root-cause determination."""
    if not isinstance(text, str):
        raise TypeError("report must be a string")
    t = text.lower()
    ranked: list[tuple[float, str, list[str]]] = []
    for name, data in ROOT_CAUSE_CLASSES.items():
        if name == "UNKNOWN_ROOT_CAUSE":
            continue
        hits = []
        for k in data["keywords"]:
            matched = bool(re.search(k, t)) if k == "expected.*got" else bool(re.search(_keyword_pattern(k), t))
            if matched:
                hits.append(k)
        if hits:
            score = len(hits) / len(data["keywords"])
            score += sum(.12 for bt in data["bug_types"] if bt.lower() in t)
            ranked.append((round(score, 4), name, hits))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    if not ranked:
        data = ROOT_CAUSE_CLASSES["UNKNOWN_ROOT_CAUSE"]
        return {"root_cause": "UNKNOWN_ROOT_CAUSE", "confidence": None, "score": 0.0, "evidence": [], "description": data["description"], "fix_pattern": data["fix_pattern"], "alternatives": [], "assessment": "hypothesis_only"}
    score, name, hits = ranked[0]
    data = ROOT_CAUSE_CLASSES[name]
    return {"root_cause": name, "confidence": None, "score": score, "evidence": hits, "description": data["description"], "fix_pattern": data["fix_pattern"], "bug_types": data["bug_types"], "alternatives": [{"root_cause": n, "score": s, "evidence": h} for s, n, h in ranked[1:4]], "assessment": "hypothesis_only"}
