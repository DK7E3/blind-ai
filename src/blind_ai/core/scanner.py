"""Deterministic Layer 2 scanner combining Regex, Shannon entropy, and Python AST.

Uses only the Python 3.12 standard library. Detects structured secrets,
high-entropy tokens, private IP addresses, and internal filesystem paths.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import ipaddress
import math
import re

_URL_RE = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s\"'<>()]+")

_URL_CREDENTIALS_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://[^/\s\"'<>():@]{1,256}:(?P<secret>[^/\s\"'<>()@]{1,512})@[^/\s\"'<>()]+"
)

_BEARER_TOKEN_RE = re.compile(
    r"(?i)\b(?:Authorization\s*[:=]\s*)?Bearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{16,})(?![A-Za-z0-9._~+/=-])"
)

_MIME_TYPE_RE = re.compile(
    r"^(?:application|text|image|audio|video|multipart|font|model|message)/[A-Za-z0-9.+_-]+(?:\s*;\s*[A-Za-z0-9._-]+=[A-Za-z0-9._-]+)*$"
)

_REGEX_LIKE_CHARS: frozenset[str] = frozenset("^$*+?()[]{}|\\")

_SEQUENTIAL_ALPHABET_SUBSTRINGS: tuple[str, ...] = (
    "0123456789abcdef",
    "0123456789ABCDEF",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
)

_NON_PYTHON_SENSITIVE_ASSIGN_RE = re.compile(
    r"""(?mx)
    (?:^|[ \t{,;])
    ["']?(?P<name>[A-Za-z_][A-Za-z0-9_-]{1,63})["']?
    [ \t]*(?::[ \t]*[A-Za-z0-9_<>\[\]|.?]+[ \t]*)?
    (?:=|:=|:)
    [ \t]*(?:["'`](?P<qvalue>[^"'`\r\n]{16,})["'`]|(?P<uvalue>[^\s"'`#;,{}()\[\]]{16,}))
    """
)

_REGEX_RULES: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "aws_access_key",
        re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
        0.98,
    ),
    (
        "anthropic_api_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"
        ),
        0.99,
    ),
    (
        "openai_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
        0.98,
    ),
    (
        "stripe_api_key",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9_])"
        ),
        0.98,
    ),
    (
        "slack_token",
        re.compile(
            r"(?<![A-Za-z0-9_-])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9_-])"
        ),
        0.98,
    ),
    (
        "google_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
        0.98,
    ),
    (
        "github_token",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])"
        ),
        0.98,
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
        ),
        0.95,
    ),
    (
        "pem_private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----[\s\S]{1,16384}?-----END (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----"
            r"|-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----"
        ),
        0.99,
    ),
)

_IPV4_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9]|\.\d)")

_UNIX_INTERNAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./:-])"
    r"/(?:srv|etc|var|opt|home|root|mnt|media|private|Users|Volumes|internal|secrets|data|app|config|run|tmp)"
    r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*"
)

_WINDOWS_INTERNAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"[A-Za-z]:(?:\\{1,2}[A-Za-z0-9._$-]+){2,}"
)

_SENSITIVE_NAME_HINTS: tuple[str, ...] = (
    "secret",
    "token",
    "key",
    "pass",
    "pwd",
    "auth",
    "cred",
    "bearer",
    "private",
    "signature",
)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single deterministic security finding in scanned text."""

    kind: str
    value: str
    start: int
    end: int
    line: int
    source: str
    confidence: float


def shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy (bits per character) of *text*."""
    if not text:
        return 0.0

    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    length = len(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def _line_number(text: str, offset: int) -> int:
    """Return the 1-based line number for character *offset* in *text*."""
    return text.count("\n", 0, offset) + 1


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Return True if half-open intervals [a_start, a_end) and [b_start, b_end) overlap."""
    return a_start < b_end and b_start < a_end


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SENSITIVE_NAME_HINTS)


def _extract_target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
        return names
    return []


def _fold_string_binop(node: ast.AST) -> str | None:
    """Recursively fold ``"a" + "b"`` AST nodes into a single combined string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_string_binop(node.left)
        right = _fold_string_binop(node.right)
        if left is not None and right is not None:
            return left + right
    return None


class DeterministicScanner:
    """Layer 2 deterministic scanner using Regex, Shannon entropy, and Python AST."""

    def __init__(
        self,
        *,
        min_entropy: float = 3.8,
        min_token_length: int = 20,
    ) -> None:
        self.min_entropy = min_entropy
        self.min_token_length = min_token_length

    def scan_text(self, text: str) -> list[Finding]:
        """Scan *text* and return deduplicated deterministic findings."""
        if not text:
            return []

        candidates: list[Finding] = []
        candidates.extend(self._scan_regex(text))
        candidates.extend(self._scan_ast_entropy(text))
        return self._deduplicate(candidates)

    def _scan_regex(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        url_spans = [(m.start(), m.end()) for m in _URL_RE.finditer(text)]

        for kind, pattern, confidence in _REGEX_RULES:
            for match in pattern.finditer(text):
                start, end = match.span()
                findings.append(
                    Finding(
                        kind=kind,
                        value=match.group(0),
                        start=start,
                        end=end,
                        line=_line_number(text, start),
                        source="regex",
                        confidence=confidence,
                    )
                )

        for match in _URL_CREDENTIALS_RE.finditer(text):
            start, end = match.span("secret")
            secret = match.group("secret")
            if not secret or secret.startswith("__BLIND_"):
                continue
            findings.append(
                Finding(
                    kind="url_credentials",
                    value=secret,
                    start=start,
                    end=end,
                    line=_line_number(text, start),
                    source="regex",
                    confidence=0.97,
                )
            )

        for match in _BEARER_TOKEN_RE.finditer(text):
            start, end = match.span("secret")
            token = match.group("secret")
            if not token or token.startswith("__BLIND_"):
                continue
            findings.append(
                Finding(
                    kind="bearer_token",
                    value=token,
                    start=start,
                    end=end,
                    line=_line_number(text, start),
                    source="regex",
                    confidence=0.92,
                )
            )

        for match in _IPV4_RE.finditer(text):
            raw_ip = match.group(0)
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
            if (
                ip_obj.is_private
                and not ip_obj.is_loopback
                and not ip_obj.is_unspecified
                and not raw_ip.startswith("0.")
            ):
                start, end = match.span()
                findings.append(
                    Finding(
                        kind="private_ip",
                        value=raw_ip,
                        start=start,
                        end=end,
                        line=_line_number(text, start),
                        source="regex",
                        confidence=0.90,
                    )
                )

        for pattern in (_UNIX_INTERNAL_PATH_RE, _WINDOWS_INTERNAL_PATH_RE):
            for match in pattern.finditer(text):
                start, end = match.span()
                if any(_spans_overlap(start, end, u_s, u_e) for u_s, u_e in url_spans):
                    continue
                findings.append(
                    Finding(
                        kind="internal_path",
                        value=match.group(0),
                        start=start,
                        end=end,
                        line=_line_number(text, start),
                        source="regex",
                        confidence=0.85,
                    )
                )

        return findings

    def _scan_ast_entropy(self, text: str) -> list[Finding]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return self._scan_non_python_sensitive_assignments(text)

        docstring_ids: set[int] = set()
        sensitive_value_ids: set[int] = set()

        for node in ast.walk(tree):
            if isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    docstring_ids.add(id(node.body[0].value))

            if isinstance(node, ast.Assign):
                if any(
                    _is_sensitive_name(name)
                    for target in node.targets
                    for name in _extract_target_names(target)
                ):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        sensitive_value_ids.add(id(node.value))
                    elif isinstance(node.value, ast.BinOp):
                        sensitive_value_ids.add(id(node.value))

            elif isinstance(node, ast.AnnAssign):
                if any(
                    _is_sensitive_name(name)
                    for name in _extract_target_names(node.target)
                ):
                    if node.value is not None and isinstance(
                        node.value, ast.Constant
                    ) and isinstance(node.value.value, str):
                        sensitive_value_ids.add(id(node.value))
                    elif node.value is None and isinstance(
                        node.annotation, ast.Constant
                    ) and isinstance(node.annotation.value, str):
                        # Catches YAML `api_secret: "..."` parsed as Python type annotation
                        sensitive_value_ids.add(id(node.annotation))

            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg
                        and _is_sensitive_name(kw.arg)
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        sensitive_value_ids.add(id(kw.value))
                if (
                    len(node.args) >= 2
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and _is_sensitive_name(node.args[0].value)
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    sensitive_value_ids.add(id(node.args[1]))

            elif isinstance(node, ast.Dict):
                for key_node, val_node in zip(node.keys, node.values):
                    if (
                        isinstance(key_node, ast.Constant)
                        and isinstance(key_node.value, str)
                        and _is_sensitive_name(key_node.value)
                        and isinstance(val_node, ast.Constant)
                        and isinstance(val_node.value, str)
                    ):
                        sensitive_value_ids.add(id(val_node))

        lines = text.splitlines(keepends=True)
        line_offsets: list[int] = []
        running = 0
        for line_str in lines:
            line_offsets.append(running)
            running += len(line_str)

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                folded = _fold_string_binop(node)
                if folded is not None:
                    in_sensitive = id(node) in sensitive_value_ids
                    matched_kind: str | None = None
                    matched_conf = 0.88 if in_sensitive else 0.82
                    for kind, pattern, conf in _REGEX_RULES:
                        if pattern.search(folded):
                            matched_kind = kind
                            matched_conf = conf
                            break
                    if matched_kind is None and self._is_high_entropy_token(
                        folded, sensitive_context=in_sensitive
                    ):
                        matched_kind = "high_entropy_token"
                    if matched_kind is not None:
                        start, end = self._node_span(text, lines, line_offsets, node, "")
                        findings.append(
                            Finding(
                                kind=matched_kind,
                                value=text[start:end],
                                start=start,
                                end=end,
                                line=node.lineno,
                                source="ast_entropy",
                                confidence=matched_conf,
                            )
                        )
                continue

            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in docstring_ids:
                continue

            value = node.value
            in_sensitive = id(node) in sensitive_value_ids
            if not self._is_high_entropy_token(value, sensitive_context=in_sensitive):
                continue

            start, end = self._node_span(text, lines, line_offsets, node, value)
            findings.append(
                Finding(
                    kind="high_entropy_token",
                    value=value,
                    start=start,
                    end=end,
                    line=node.lineno,
                    source="ast_entropy",
                    confidence=0.88 if in_sensitive else 0.80,
                )
            )

        return findings

    def _scan_non_python_sensitive_assignments(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _NON_PYTHON_SENSITIVE_ASSIGN_RE.finditer(text):
            name = match.group("name")
            if not _is_sensitive_name(name):
                continue
            group_name = "qvalue" if match.group("qvalue") is not None else "uvalue"
            value = match.group(group_name)
            if not value or not self._is_high_entropy_token(value, sensitive_context=True):
                continue
            start, end = match.span(group_name)
            findings.append(
                Finding(
                    kind="high_entropy_token",
                    value=value,
                    start=start,
                    end=end,
                    line=_line_number(text, start),
                    source="ast_entropy",
                    confidence=0.88,
                )
            )
        return findings

    def _is_high_entropy_token(self, value: str, *, sensitive_context: bool) -> bool:
        if len(value) < self.min_token_length:
            return False
        if any(ch.isspace() for ch in value):
            return False
        if value.startswith("__BLIND_") and value.endswith("__"):
            return False
        if _URL_RE.match(value):
            return False
        if _MIME_TYPE_RE.match(value):
            return False
        if value.startswith("^") and value.endswith("$"):
            return False
        if any(seq in value for seq in _SEQUENTIAL_ALPHABET_SUBSTRINGS):
            return False
        if shannon_entropy(value) < self.min_entropy:
            return False

        if sensitive_context:
            return True

        if any(ch in _REGEX_LIKE_CHARS for ch in value):
            return False

        has_lower = any(ch.islower() for ch in value)
        has_upper = any(ch.isupper() for ch in value)
        has_digit = any(ch.isdigit() for ch in value)
        if not has_digit:
            return False
        class_count = int(has_lower) + int(has_upper) + int(has_digit)
        return class_count >= 2

    @staticmethod
    def _node_span(
        text: str,
        lines: list[str],
        line_offsets: list[int],
        node: ast.Constant,
        value: str,
    ) -> tuple[int, int]:
        lineno = node.lineno
        end_lineno = node.end_lineno or lineno
        col = node.col_offset
        end_col = node.end_col_offset if node.end_col_offset is not None else col

        start_line_str = lines[lineno - 1]
        end_line_str = lines[end_lineno - 1]
        char_col = len(start_line_str.encode("utf-8")[:col].decode("utf-8"))
        end_char_col = len(end_line_str.encode("utf-8")[:end_col].decode("utf-8"))

        abs_start = line_offsets[lineno - 1] + char_col
        abs_end = line_offsets[end_lineno - 1] + end_char_col

        raw_slice = text[abs_start:abs_end]
        if value:
            inner_pos = raw_slice.find(value)
            if inner_pos != -1:
                return abs_start + inner_pos, abs_start + inner_pos + len(value)
        return abs_start, abs_end

    @staticmethod
    def _deduplicate(candidates: list[Finding]) -> list[Finding]:
        ranked = sorted(
            candidates,
            key=lambda f: (-f.confidence, -(f.end - f.start), f.start, f.kind),
        )
        accepted: list[Finding] = []
        for candidate in ranked:
            if any(
                _spans_overlap(candidate.start, candidate.end, kept.start, kept.end)
                for kept in accepted
            ):
                continue
            accepted.append(candidate)

        accepted.sort(key=lambda f: (f.start, f.end, f.kind))
        return accepted
