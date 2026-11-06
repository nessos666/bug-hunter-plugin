"""AST scanner: bindings, scopes, findings. Read-only, never executes code."""
from __future__ import annotations

import ast
import fnmatch
import io
import os
import stat
import tokenize
from pathlib import Path

from .core import (DEFAULT_EXCLUDES, MAX_DEFAULT_BYTES, Finding,
                   _content_fingerprint, _fingerprint, _limit_diagnostic)
from .rules import RULES

__all__ = ["Scanner", "Finding", "scan_source", "scan_file", "scan_path"]

class Scanner(ast.NodeVisitor):
    """Conservative syntactic scanner with lexical import/assignment shadow tracking.

    This is NOT whole-program symbol resolution or taint analysis. Findings are
    candidate risks requiring review; do not treat them as proven exploits.
    """
    def __init__(self, path: str = "<memory>", lines: list[str] | None = None) -> None:
        self.path = path
        self.lines = lines or []
        self.findings: list[Finding] = []
        self.scopes: list[dict[str, str | None]] = [{}]
        self.scope_kind: list[str] = ["module"]
        self._func_depth = 0
        self.context_open: set[int] = set()
        self._occurrence: dict[tuple[str, str], int] = {}

    def emit(self, rule: str, node: ast.AST, detail: str = "") -> None:
        rc, cwe, severity, desc, fix = RULES[rule]
        line, col = getattr(node, "lineno", 1), getattr(node, "col_offset", 0)
        message = desc + (": " + detail if detail else "")
        snippet = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        key = (rule, " ".join(snippet.split()))
        occurrence = self._occurrence.get(key, 0)
        self._occurrence[key] = occurrence + 1
        self.findings.append(Finding(rule, self.path, line, col + 1, message, severity, rc, cwe, fix, _content_fingerprint(rule, self.path, snippet, occurrence)))

    def resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            seen_function = False
            for kind, scope in zip(reversed(self.scope_kind), reversed(self.scopes)):
                if kind in ("function", "lambda"):
                    seen_function = True
                if kind == "class" and seen_function:
                    continue  # methods do not see the class namespace
                if node.id in scope:
                    return scope[node.id]
            return node.id if node.id in {"eval", "exec", "compile", "open"} else None
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            base = self.resolve(node.func)
            return "pathlib.Path" if base in {"pathlib.Path", "Path"} else None
        return None

    def bind(self, name: str, origin: str | None = None) -> None:
        self.scopes[-1][name] = origin

    def bind_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.bind(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.bind_target(child)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.bind(alias.asname or alias.name.split(".")[0], alias.name if alias.asname else alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            for alias in node.names:
                if alias.name != "*":
                    self.bind(alias.asname or alias.name, alias.name)
            return
        for alias in node.names:
            if alias.name != "*":
                self.bind(alias.asname or alias.name, f"{node.module}.{alias.name}" if node.module else None)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            origin = self.resolve(node.value)
            if isinstance(target, ast.Name):
                self.bind(target.id, origin)
            else:
                self.bind_target(target)
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self.scope_kind[-1] in ("module", "class"):
            self.visit(node.annotation)  # module/class annotations are evaluated
        if node.value is not None:
            self.visit(node.value)
            origin = self.resolve(node.value)
            if isinstance(node.target, ast.Name):
                self.bind(node.target.id, origin)
            else:
                self.bind_target(node.target)
                self.visit(node.target)
        # a bare annotation does not create a binding at runtime

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self.bind_target(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self.visit(node.target)
        self.bind_target(node.target)

    def prebind(self, tree: ast.AST) -> None:
        """Bind module-level imports first so forward references resolve."""
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.visit(node)

    def _visit_all(self, nodes) -> None:
        for stmt in nodes:
            self.visit(stmt)

    @staticmethod
    def _combine(previous, values):
        known = {v for v in values if v is not None}
        if len(known) == 1:
            return known.pop()
        if not known:
            return previous
        return None

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        snapshot = dict(self.scopes[-1])
        self._visit_all(node.body)
        body_scope = dict(self.scopes[-1])
        self.scopes[-1] = dict(snapshot)
        self._visit_all(node.orelse)
        else_scope = dict(self.scopes[-1])
        merged = dict(snapshot)
        for name in set(body_scope) | set(else_scope):
            merged[name] = self._combine(snapshot.get(name), [body_scope.get(name), else_scope.get(name)])
        self.scopes[-1] = merged

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self.bind_target(node.target)
        snapshot = dict(self.scopes[-1])
        self._visit_all(node.body + node.orelse)
        body_scope = dict(self.scopes[-1])
        merged = dict(snapshot)
        for name in set(body_scope) | set(snapshot):
            merged[name] = self._combine(snapshot.get(name), [body_scope.get(name), snapshot.get(name)])
        self.scopes[-1] = merged
    visit_AsyncFor = visit_For

    def visit_Try(self, node) -> None:
        snapshot = dict(self.scopes[-1])
        self._visit_all(node.body)
        body_scope = dict(self.scopes[-1])
        self.scopes[-1] = dict(snapshot)
        self._visit_all(node.handlers)
        self._visit_all(node.orelse)
        handled = dict(self.scopes[-1])
        merged = dict(snapshot)
        for name in set(body_scope) | set(handled):
            merged[name] = self._combine(snapshot.get(name), [body_scope.get(name), handled.get(name)])
        self.scopes[-1] = merged
        self._visit_all(node.finalbody)
    visit_TryStar = visit_Try

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and self.resolve(item.context_expr.func) in {"open", "io.open", "pathlib.Path.open"}:
                self.context_open.add(id(item.context_expr))
            self.visit(item.context_expr)
            if item.optional_vars:
                self.bind_target(item.optional_vars)
        snapshot = dict(self.scopes[-1])
        self._visit_all(node.body)
        body_scope = dict(self.scopes[-1])
        merged = dict(snapshot)
        for name in set(body_scope) | set(snapshot):
            merged[name] = self._combine(snapshot.get(name), [body_scope.get(name), snapshot.get(name)])
        self.scopes[-1] = merged
    visit_AsyncWith = visit_With

    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        if name and name.startswith("builtins."):
            name = name[len("builtins."):]
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.emit("BH001", node, name)
        elif name in {"compile", "builtins.compile"}:
            self.emit("BH013", node, name)
        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "dill.load", "dill.loads"}:
            self.emit("BH002", node, name)
        if name in {"yaml.unsafe_load", "yaml.unsafe_load_all"}:
            self.emit("BH010", node, name)
        if name in {"yaml.load", "yaml.load_all"}:
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            loader_name = self.resolve(loader) if loader is not None else None
            unsafe_loaders = {"yaml.Loader", "yaml.UnsafeLoader", "yaml.CLoader", "yaml.CUnsafeLoader",
                              "Loader", "UnsafeLoader", "CLoader", "CUnsafeLoader"}
            if loader is None:
                self.emit("BH014", node, "no Loader given")
            elif loader_name in unsafe_loaders:
                self.emit("BH003", node, loader_name)
        if name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}:
            self.emit("BH004", node, name)
        subprocess_names = {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"}
        if name in subprocess_names:
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}
            unknown_kwargs = any(kw.arg is None for kw in node.keywords)
            shell_value = keywords.get("shell")
            shell_flag = False
            if shell_value is not None:
                if isinstance(shell_value, ast.Constant):
                    shell_flag = bool(shell_value.value)
                else:
                    shell_flag = True  # dynamic value: risky, not assumed safe
            if not shell_flag and not unknown_kwargs and name == "subprocess.Popen" and len(node.args) > 8:
                arg8 = node.args[8]
                shell_flag = isinstance(arg8, ast.Constant) and bool(arg8.value)
            if shell_flag:
                self.emit("BH012", node, name)
            timeout_value = keywords.get("timeout")
            has_timeout = timeout_value is not None and not (isinstance(timeout_value, ast.Constant) and timeout_value.value is None)
            if unknown_kwargs:
                pass  # timeout may be supplied; do not guess
            elif name not in {"subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput"} and not has_timeout:
                self.emit("BH009", node, name)
        if name in {"open", "io.open", "pathlib.Path.open"} and id(node) not in self.context_open:
            self.emit("BH008", node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.emit("BH005", node)
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.emit("BH011", node)
        if node.type:
            self.visit(node.type)
        if node.name:
            self.bind(node.name)
        for stmt in node.body:
            self.visit(stmt)

    def visit_Compare(self, node: ast.Compare) -> None:
        parts = [node.left] + node.comparators
        for i, op in enumerate(node.ops):
            if isinstance(op, (ast.Eq, ast.NotEq)) and any(isinstance(p, ast.Constant) and p.value is None for p in parts[i:i+2]):
                self.emit("BH006", node)
                break
        self.generic_visit(node)

    def _check_mutable_defaults(self, defaults) -> None:
        for value in defaults:
            if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                self.emit("BH007", value)
            elif (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                  and value.func.id in {"list", "dict", "set"} and value.func.id not in self.scopes[-1]):
                self.emit("BH007", value)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = list(node.args.defaults) + [x for x in node.args.kw_defaults if x is not None]
        self._check_mutable_defaults(defaults)
        # Decorators, defaults and annotations execute in the outer scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in defaults:
            self.visit(default)
        args = node.args
        all_args = args.posonlyargs + args.args + args.kwonlyargs + ([args.vararg] if args.vararg else []) + ([args.kwarg] if args.kwarg else [])
        for arg in all_args:
            if arg.annotation:
                self.visit(arg.annotation)
        if node.returns:
            self.visit(node.returns)
        self.bind(node.name)
        self.scopes.append({})
        self.scope_kind.append("function")
        self._func_depth += 1
        for arg in all_args:
            self.bind(arg.arg)
        for stmt in node.body:
            self.visit(stmt)
        self._func_depth -= 1
        self.scope_kind.pop()
        self.scopes.pop()
    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.bind(node.name)
        self.scopes.append({})
        self.scope_kind.append("class")
        for stmt in node.body:
            self.visit(stmt)
        self.scope_kind.pop()
        self.scopes.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._check_mutable_defaults(list(node.args.defaults) + [x for x in node.args.kw_defaults if x is not None])
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)
        self.scopes.append({})
        self.scope_kind.append("lambda")
        self._func_depth += 1
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.bind(arg.arg)
        if node.args.vararg:
            self.bind(node.args.vararg.arg)
        if node.args.kwarg:
            self.bind(node.args.kwarg.arg)
        self.visit(node.body)
        self._func_depth -= 1
        self.scope_kind.pop()
        self.scopes.pop()

def scan_source(source: str, path: str = "<memory>") -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as exc:
        line = max(1, getattr(exc, "lineno", 1) or 1)
        message = f"Syntax/parse error: {exc}"
        return [Finding("BH_PARSE", path, line, max(1, getattr(exc, "offset", 1) or 1), message, "ERROR", "UNKNOWN_ROOT_CAUSE", None, "Fix source syntax before scanning", _fingerprint("BH_PARSE", path, line, 1, message), "certain")]
    except RecursionError as exc:
        return [_limit_diagnostic(path, exc)]
    scanner = Scanner(path, source.splitlines())
    scanner.prebind(tree)
    try:
        scanner.visit(tree)
    except RecursionError as exc:
        return sorted(scanner.findings + [_limit_diagnostic(path, exc)], key=lambda f: (f.line, f.column, f.rule_id))
    return sorted(scanner.findings, key=lambda f: (f.line, f.column, f.rule_id))

def _diag(path: str, message: str, rule: str = "BH_IO") -> Finding:
    return Finding(rule, path, 1, 1, message, "ERROR", "UNKNOWN_ROOT_CAUSE", None, "Review input path and permissions", _fingerprint(rule, path, 1, 1, message), "certain")

def scan_file(path: str | Path, max_bytes: int = MAX_DEFAULT_BYTES) -> list[Finding]:
    path = str(path)
    file_descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        file_descriptor = os.open(path, flags)
        stat_result = os.fstat(file_descriptor)
        if not stat.S_ISREG(stat_result.st_mode):
            return [_diag(path, "Not a regular file; refusing to read (special file)")]
        if stat_result.st_size > max_bytes:
            return [_diag(path, f"File exceeds size limit ({max_bytes} bytes)", "BH_LIMIT")]
        with os.fdopen(file_descriptor, "rb") as handle:
            file_descriptor = -1  # ownership moved to the file object
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return [_diag(path, f"File exceeds size limit ({max_bytes} bytes)", "BH_LIMIT")]
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        except SyntaxError:
            return [Finding("BH_SKIP", path, 1, 1, "Unknown source encoding; file not scanned", "NOTE",
                            "UNKNOWN_ROOT_CAUSE", None, "Convert the file to UTF-8",
                            _fingerprint("BH_SKIP", path, 1, 1, "encoding"), "certain")]
        return scan_source(raw.decode(encoding, errors="replace"), path)
    except (OSError, UnicodeError, SyntaxError, LookupError) as exc:
        return [_diag(path, f"Could not read file: {type(exc).__name__}: {exc}")]
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)

def scan_path(path: str | Path, *, max_bytes: int = MAX_DEFAULT_BYTES, excludes: tuple[str, ...] = DEFAULT_EXCLUDES, follow_symlinks: bool = False, max_files: int = 20000) -> list[Finding]:
    path = Path(path)
    if not path.exists():
        return [_diag(str(path), "Input path does not exist")]
    if path.is_file():
        return scan_file(path, max_bytes)
    if not path.is_dir():
        return [_diag(str(path), "Input is not a regular file or directory")]
    findings: list[Finding] = []
    count = 0
    skipped_symlinks = 0
    seen_dirs: set[tuple[int, int]] = set()

    def _on_error(error: OSError) -> None:
        findings.append(_diag(str(getattr(error, "filename", path)), f"Could not read directory: {error.strerror or error}"))

    for root, dirs, files in os.walk(path, followlinks=follow_symlinks, onerror=_on_error):
        try:
            st = os.stat(root)
            dir_key = (st.st_dev, st.st_ino)
        except OSError:
            dir_key = None
        if dir_key is not None:
            if dir_key in seen_dirs:
                dirs[:] = []
                continue
            seen_dirs.add(dir_key)
        dirs[:] = sorted(d for d in dirs if not any(fnmatch.fnmatch(d, pattern) for pattern in excludes) and (follow_symlinks or not (Path(root) / d).is_symlink()))
        for filename in sorted(files):
            full = Path(root) / filename
            if not filename.endswith(".py") or any(fnmatch.fnmatch(filename, p) for p in excludes):
                continue
            if full.is_symlink() and not follow_symlinks:
                skipped_symlinks += 1
                continue
            if count >= max_files:
                findings.append(_diag(str(path), f"Maximum file count reached ({max_files})", "BH_LIMIT"))
                return sorted(findings, key=lambda f: (f.file, f.line, f.column, f.rule_id))
            count += 1
            findings.extend(scan_file(full, max_bytes))
    if skipped_symlinks:
        skip_message = f"{skipped_symlinks} symlinked .py file(s) skipped (follow_symlinks=False)"
        findings.append(Finding("BH_SKIP", str(path), 1, 1, skip_message, "NOTE", "UNKNOWN_ROOT_CAUSE", None,
                                "Enable follow_symlinks to include them",
                                _fingerprint("BH_SKIP", str(path), 1, 1, skip_message), "certain"))
    return sorted(findings, key=lambda f: (f.file, f.line, f.column, f.rule_id))
