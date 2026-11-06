"""Tests für das Hermes-Plugin bug-hunter.

Läuft ohne Hermes-Installation: das Plugin wird direkt geladen und mit einem
Fake-ctx registriert. Geprüft wird der echte Aufrufvertrag (genau ein Argument),
nicht nur die Registrierung.
"""
import importlib.util
import inspect
import json
import os
import sys

import pytest

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    spec = importlib.util.spec_from_file_location(
        "bh_plugin_under_test", os.path.join(PLUGIN_DIR, "__init__.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    def __init__(self):
        self.commands = {}
        self.tools = {}

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = (schema, handler)

    def register_system_prompt_section(self, *a, **k):
        pass


@pytest.fixture(scope="module")
def plugin():
    mod = _load()
    ctx = FakeCtx()
    mod.register(ctx)
    return mod, ctx


@pytest.fixture
def baddir(tmp_path):
    d = tmp_path / "code"
    d.mkdir()
    (d / "bad.py").write_text(
        "import pickle\n"
        "def f(x={}):\n"
        "    return eval(x)\n"
        "try:\n"
        "    pickle.loads(b'x')\n"
        "except:\n"
        "    pass\n",
        encoding="utf-8",
    )
    return str(d)


def test_registers_both_commands_and_tool(plugin):
    _, ctx = plugin
    assert set(ctx.commands) == {"bugscan", "bugrules"}
    assert "bug_scan" in ctx.tools


def test_handlers_take_exactly_one_argument(plugin):
    _, ctx = plugin
    for name, handler in ctx.commands.items():
        sig = inspect.signature(handler, follow_wrapped=False)
        sig.bind("x")  # wirft TypeError, wenn der Vertrag verletzt ist
        assert len([p for p in sig.parameters.values()
                    if p.kind is p.POSITIONAL_OR_KEYWORD]) == 1, name


def test_bugscan_reports_findings(plugin, baddir):
    _, ctx = plugin
    res = ctx.commands["bugscan"](baddir)
    assert res["status"] == "ok"
    assert "Befund" in res["message"]
    assert "BH001" in res["message"] or "BH002" in res["message"]


def test_bugscan_missing_path_is_error(plugin, tmp_path):
    _, ctx = plugin
    res = ctx.commands["bugscan"](str(tmp_path / "gibt-es-nicht"))
    assert res["status"] == "error"
    assert "nicht gefunden" in res["message"]


def test_bugrules_lists_table(plugin):
    _, ctx = plugin
    res = ctx.commands["bugrules"]("")
    assert res["status"] == "ok"
    assert "BH001" in res["message"]
    assert "BH014" in res["message"]


def test_tool_json_shape(plugin, baddir):
    _, ctx = plugin
    _, handler = ctx.tools["bug_scan"]
    data = json.loads(handler({"path": baddir, "format": "json"}))
    assert data["count"] == len(data["findings"])
    assert {"ERROR", "WARNING", "NOTE"} >= set(data["summary"])
    assert all({"rule_id", "file", "line", "severity", "fingerprint"} <= set(f)
               for f in data["findings"])


def test_tool_sarif_is_2_1_0(plugin, baddir):
    _, ctx = plugin
    _, handler = ctx.tools["bug_scan"]
    doc = json.loads(handler({"path": baddir, "format": "sarif"}))
    assert doc["version"] == "2.1.0"
    assert doc["runs"]


def test_tool_severity_filter(plugin, baddir):
    _, ctx = plugin
    _, handler = ctx.tools["bug_scan"]
    alles = json.loads(handler({"path": baddir, "format": "json"}))
    nur_fehler = json.loads(handler({"path": baddir, "format": "json", "severity": "ERROR"}))
    assert nur_fehler["count"] <= alles["count"]
    assert all(f["severity"] == "ERROR" for f in nur_fehler["findings"])


def test_tool_without_path_is_error(plugin):
    _, ctx = plugin
    _, handler = ctx.tools["bug_scan"]
    assert handler({}).startswith("Fehler")


def test_selftest_still_green(plugin):
    mod, _ = plugin
    assert mod.scan_path is not None
    from bug_hunter import run_selftest
    assert run_selftest() is True


def test_no_network_imports(plugin):
    """Der Scanner darf kein Netzwerk anfassen."""
    quelle = ""
    for root, _dirs, files in os.walk(os.path.join(PLUGIN_DIR, "bug_hunter")):
        for f in files:
            if f.endswith(".py"):
                quelle += open(os.path.join(root, f), encoding="utf-8").read()
    for verboten in ("import socket", "import requests", "urllib.request", "http.client"):
        assert verboten not in quelle, f"Netzwerkzugriff gefunden: {verboten}"
