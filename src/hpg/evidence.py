"""Python source heuristics and SARIF location verification for the benchmark."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import tokenize
from collections import Counter
from dataclasses import dataclass


SQL_INJECTION = "CWE-89"
COMMAND_INJECTION = "CWE-78"
AUTH_BYPASS = "CWE-287"
SSRF = "CWE-918"
PATH_TRAVERSAL = "CWE-22"
RULES = (SQL_INJECTION, COMMAND_INJECTION, AUTH_BYPASS, SSRF, PATH_TRAVERSAL)


@dataclass(frozen=True)
class CodeEntity:
    rule_id: str
    line: int
    end_line: int
    quote: str
    entity_hash: str


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_qualified_name(node.value)}.{node.attr}"
    return ""


def _literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return False
    return True


def _dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) and not _literal(part.value) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(not _literal(part) for part in (node.left, node.right))
    if isinstance(node, ast.Call) and _qualified_name(node.func).endswith(".format"):
        return any(not _literal(arg) for arg in node.args) or any(not _literal(kw.value) for kw in node.keywords)
    return False


def _call_rule(node: ast.Call) -> str:
    name = _qualified_name(node.func)
    if name.startswith("subprocess.") and any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in node.keywords
    ) and node.args and not _literal(node.args[0]):
        return COMMAND_INJECTION
    if not node.args:
        return ""
    argument = node.args[0]
    if name.endswith(".execute") and _dynamic_string(argument):
        return SQL_INJECTION
    if name in {"requests.get", "requests.post", "urllib.request.urlopen"} and not _literal(argument):
        return SSRF
    if name in {"open", "io.open"} and isinstance(argument, ast.BinOp) and isinstance(argument.op, ast.Div):
        if not _literal(argument.right):
            return PATH_TRAVERSAL
    return ""


def _code_tokens(quote: str) -> list[tuple[int, str]]:
    ignored = {
        tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
        tokenize.DEDENT, tokenize.ENDMARKER,
    }
    return [
        (token.type, token.string)
        for token in tokenize.generate_tokens(io.StringIO(quote).readline)
        if token.type not in ignored
    ]


class _SourceScanner(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source
        self.scope: list[str] = []
        self.occurrences: Counter[str] = Counter()
        self.entities: list[CodeEntity] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(node.name)
        statements = node.body[1:] if ast.get_docstring(node) is not None else node.body
        if node.name.startswith(("is_authorized", "check_permission")) and len(statements) == 1:
            statement = statements[0]
            if (
                isinstance(statement, ast.Return)
                and isinstance(statement.value, ast.Constant)
                and statement.value.value is True
            ):
                self._record(AUTH_BYPASS, statement)
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _record(self, rule_id: str, node: ast.AST) -> None:
        quote = ast.get_source_segment(self.source, node)
        identity = json.dumps([rule_id, self.scope, _code_tokens(quote)])
        occurrence = self.occurrences[identity]
        self.occurrences[identity] += 1
        digest = hashlib.sha256(f"{identity}:{occurrence}".encode("utf-8")).hexdigest()
        self.entities.append(CodeEntity(rule_id, node.lineno, node.end_lineno, quote, digest))

    def visit_Call(self, node: ast.Call) -> None:
        rule_id = _call_rule(node)
        if rule_id:
            self._record(rule_id, node)
        self.generic_visit(node)


def scan_python(source: str) -> tuple[CodeEntity, ...]:
    scanner = _SourceScanner(source)
    scanner.visit(ast.parse(source))
    return tuple(scanner.entities)


def _objects(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _object(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def sarif_locations(report: dict, path: str, source: str) -> set[tuple[str, int]]:
    """Read SARIF 2.1.0 locations for a file, verifying any supplied source snippet."""
    if _object(report).get("version") != "2.1.0":
        return set()
    lines = source.splitlines()
    locations = set()
    for run in _objects(report.get("runs")):
        for result in _objects(run.get("results")):
            rule_id = result.get("ruleId")
            if rule_id not in RULES:
                continue
            for location in _objects(result.get("locations")):
                physical = _object(location.get("physicalLocation"))
                if _object(physical.get("artifactLocation")).get("uri") != path:
                    continue
                region = _object(physical.get("region"))
                line = region.get("startLine")
                if type(line) is not int or not 1 <= line <= len(lines):
                    continue
                if "snippet" in region:
                    text = _object(region["snippet"]).get("text")
                    if not isinstance(text, str) or text.rstrip() != lines[line - 1].rstrip():
                        continue
                locations.add((rule_id, line))
    return locations
