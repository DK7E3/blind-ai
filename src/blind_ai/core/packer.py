"""Repository context packer with shared pseudonymization vault.

Uses only the Python 3.12 standard library. Recursively scans a directory in
deterministic order, respects technical directory exclusions, basic
``.gitignore`` patterns, and :class:`~blind_ai.core.file_filter.FileFilter`,
and sanitizes all included files through a single shared
:class:`~blind_ai.core.vault.PseudonymVault` so repeated secrets, private IPs,
and proprietary terms map to identical placeholders across files.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import fnmatch
import os
from pathlib import Path
import re
from typing import Any, Protocol

from blind_ai.core.config import BlindAIConfig
from blind_ai.core.contextual import HybridScanner
from blind_ai.core.file_filter import FileFilter
from blind_ai.core.scanner import (
    DeterministicScanner,
    Finding,
    _line_number,
    _spans_overlap,
)
from blind_ai.core.vault import PseudonymVault

TECHNICAL_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)

DEFAULT_LOCKFILE_PATTERNS: tuple[str, ...] = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "*.min.js",
    "*.min.css",
)

DEFAULT_MAX_FILE_BYTES = 1_000_000

_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "jsx",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".json": "json",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".md": "markdown",
    ".sh": "bash",
    ".bash": "bash",
    ".ps1": "powershell",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".xml": "xml",
    ".ini": "ini",
    ".cfg": "ini",
    ".txt": "text",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
}

_BACKTICK_RUN_RE = re.compile(r"`+")


class ScannerProtocol(Protocol):
    """Minimal scanner interface satisfied by DeterministicScanner and HybridScanner."""

    def scan_text(self, text: str) -> list[Finding]:
        """Scan *text* and return detected findings."""
        ...


@dataclass(frozen=True, slots=True)
class _GitignoreRule:
    """A single parsed rule from a ``.gitignore`` file."""

    pattern: str
    negated: bool
    dir_only: bool
    anchored: bool
    has_slash: bool

    def matches(self, rel_posix: str, *, is_dir: bool) -> bool:
        """Return True if *rel_posix* matches this gitignore rule."""
        if self.dir_only and not is_dir:
            return False

        candidates: list[str] = [self.pattern]
        if self.pattern.startswith("**/"):
            candidates.append(self.pattern[3:])

        basename = rel_posix.rsplit("/", 1)[-1]
        parts = rel_posix.split("/")

        for pat in candidates:
            if self.anchored:
                if fnmatch.fnmatchcase(rel_posix, pat):
                    return True
            elif self.has_slash:
                if fnmatch.fnmatchcase(rel_posix, pat):
                    return True
            else:
                if fnmatch.fnmatchcase(basename, pat) or fnmatch.fnmatchcase(
                    rel_posix, pat
                ):
                    return True
                if self.dir_only and any(
                    fnmatch.fnmatchcase(part, pat) for part in parts
                ):
                    return True
        return False


def _parse_gitignore(gitignore_path: Path) -> list[_GitignoreRule]:
    """Parse basic ``.gitignore`` rules from *gitignore_path*."""
    if not gitignore_path.is_file():
        return []

    try:
        raw_text = gitignore_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rules: list[_GitignoreRule] = []
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:].strip()
            if not line:
                continue

        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
            if not line:
                continue

        anchored = line.startswith("/")
        if anchored:
            line = line.lstrip("/")
            if not line:
                continue

        has_slash = "/" in line
        rules.append(
            _GitignoreRule(
                pattern=line,
                negated=negated,
                dir_only=dir_only,
                anchored=anchored,
                has_slash=has_slash,
            )
        )

    return rules


def _is_gitignored(
    rel_posix: str,
    rules: Sequence[_GitignoreRule],
    *,
    is_dir: bool,
) -> bool:
    """Evaluate *rel_posix* against ordered ``.gitignore`` rules."""
    ignored = False
    for rule in rules:
        if rule.matches(rel_posix, is_dir=is_dir):
            ignored = not rule.negated
    return ignored


def _fence_for_content(content: str) -> str:
    """Return a backtick fence strictly longer than any backtick run in *content*."""
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN_RE.finditer(content)), default=0)
    return "`" * max(3, longest + 1)


def _language_for_path(rel_posix: str) -> str:
    """Return a Markdown code fence language hint for *rel_posix*."""
    suffix = Path(rel_posix).suffix.lower()
    return _EXTENSION_TO_LANGUAGE.get(suffix, "")


def _render_file_tree(rel_paths: Sequence[str]) -> str:
    """Render a deterministic ASCII/Unicode file tree for *rel_paths*."""
    tree: dict[str, Any] = {}
    for rel_path in rel_paths:
        node = tree
        for part in rel_path.split("/"):
            node = node.setdefault(part, {})

    lines: list[str] = ["."]

    def _walk(node: dict[str, Any], prefix: str) -> None:
        names = sorted(node.keys())
        total = len(names)
        for index, name in enumerate(names):
            is_last = index == total - 1
            connector = "└── " if is_last else "├── "
            children = node[name]
            label = f"{name}/" if children else name
            lines.append(f"{prefix}{connector}{label}")
            if children:
                child_prefix = f"{prefix}{'    ' if is_last else '│   '}"
                _walk(children, child_prefix)

    _walk(tree, "")
    return "\n".join(lines)


def _matches_lockfile_or_minified(rel_posix: str) -> str | None:
    """Return the matched lockfile/minified pattern for *rel_posix*, or None."""
    name_lower = Path(rel_posix).name.lower()
    posix_lower = rel_posix.lower()
    for pattern in DEFAULT_LOCKFILE_PATTERNS:
        pat_lower = pattern.lower()
        if fnmatch.fnmatchcase(name_lower, pat_lower) or fnmatch.fnmatchcase(
            posix_lower, pat_lower
        ):
            return pattern
    return None


@dataclass(frozen=True, slots=True)
class PackResult:
    """Result of packing and sanitizing a repository directory for LLM context."""

    bundle: str
    included_files: list[str]
    blocked_files: list[str]
    included_count: int
    blocked_count: int
    estimated_tokens: int
    vault: PseudonymVault
    blocked_reasons: dict[str, str] = field(default_factory=dict)


@dataclass
class ContextPacker:
    """Packs a repository directory into a sanitized Markdown bundle for LLMs.

    Uses a single :class:`~blind_ai.core.vault.PseudonymVault` across all files
    to guarantee cross-file placeholder consistency for secrets, private IPs,
    internal paths, custom rules, and optional proprietary terms.
    """

    vault: PseudonymVault | None = None
    scanner: ScannerProtocol | None = None
    file_filter: FileFilter | None = None
    proprietary_terms: Sequence[str] = ()
    config: BlindAIConfig | None = None
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_tokens: int | None = None
    case_insensitive_terms: bool = False

    def __post_init__(self) -> None:
        if self.scanner is None:
            self.scanner = HybridScanner()
        if self.vault is None:
            self.vault = PseudonymVault(scanner=self.scanner)  # type: ignore[arg-type]
        if self.file_filter is None:
            if self.config is not None:
                self.file_filter = self.config.build_file_filter()
            else:
                self.file_filter = FileFilter()
        merged_terms: list[str] = list(self.proprietary_terms)
        if self.config is not None and self.config.proprietary_terms:
            merged_terms.extend(self.config.proprietary_terms)
        self.proprietary_terms = self._normalize_terms(merged_terms)

    @staticmethod
    def _normalize_terms(terms: Sequence[str]) -> tuple[str, ...]:
        """Return unique non-empty proprietary terms ordered longest-first."""
        cleaned = {term for term in terms if isinstance(term, str) and term.strip()}
        return tuple(sorted(cleaned, key=lambda t: (-len(t), t)))

    def _find_custom_rule_findings(
        self,
        text: str,
        existing_findings: Sequence[Finding],
    ) -> list[Finding]:
        """Build non-overlapping findings from ``config.compiled_custom_rules``."""
        if not text or self.config is None or not self.config.compiled_custom_rules:
            return []

        occupied_spans: list[tuple[int, int]] = [
            (finding.start, finding.end) for finding in existing_findings
        ]
        custom_findings: list[Finding] = []

        for rule_name, pattern in self.config.compiled_custom_rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                if start == end:
                    continue
                if any(
                    _spans_overlap(start, end, occ_start, occ_end)
                    for occ_start, occ_end in occupied_spans
                ):
                    continue
                occupied_spans.append((start, end))
                custom_findings.append(
                    Finding(
                        kind=rule_name,
                        value=match.group(0),
                        start=start,
                        end=end,
                        line=_line_number(text, start),
                        source="custom_rule",
                        confidence=0.95,
                    )
                )

        custom_findings.sort(key=lambda f: (f.start, f.end, f.kind))
        return custom_findings

    def _find_proprietary_terms(
        self,
        text: str,
        existing_findings: Sequence[Finding],
        terms: Sequence[str],
        *,
        case_insensitive: bool | None = None,
    ) -> list[Finding]:
        """Build non-overlapping ``Finding(kind='proprietary_term', ...)`` entries.

        Longer terms take precedence, and spans overlapping any finding already
        reported by the scanner are skipped.
        """
        if not text or not terms:
            return []

        use_case_insensitive = (
            self.case_insensitive_terms
            if case_insensitive is None
            else case_insensitive
        )
        regex_flags = re.IGNORECASE if use_case_insensitive else 0

        occupied_spans: list[tuple[int, int]] = [
            (finding.start, finding.end) for finding in existing_findings
        ]
        term_findings: list[Finding] = []

        for term in terms:
            pattern = re.compile(re.escape(term), regex_flags)
            for match in pattern.finditer(text):
                start, end = match.span()
                if any(
                    _spans_overlap(start, end, occ_start, occ_end)
                    for occ_start, occ_end in occupied_spans
                ):
                    continue
                occupied_spans.append((start, end))
                term_findings.append(
                    Finding(
                        kind="proprietary_term",
                        value=match.group(0),
                        start=start,
                        end=end,
                        line=_line_number(text, start),
                        source="proprietary_term",
                        confidence=1.0,
                    )
                )

        term_findings.sort(key=lambda f: (f.start, f.end, f.kind))
        return term_findings

    def _sanitize_content(
        self,
        text: str,
        terms: Sequence[str],
        *,
        case_insensitive: bool | None = None,
    ) -> str:
        """Scan *text* with scanner + config rules + proprietary terms and sanitize via shared vault."""
        assert self.scanner is not None
        assert self.vault is not None

        scanner_findings = list(self.scanner.scan_text(text))
        custom_findings = self._find_custom_rule_findings(text, scanner_findings)
        base_findings = [*scanner_findings, *custom_findings]
        if self.config is not None:
            base_findings = self.config.filter_findings(base_findings)

        term_findings = self._find_proprietary_terms(
            text,
            base_findings,
            terms,
            case_insensitive=case_insensitive,
        )
        if self.config is not None:
            term_findings = self.config.filter_findings(term_findings)

        combined = sorted(
            [*base_findings, *term_findings],
            key=lambda f: (f.start, f.end, f.kind),
        )
        return self.vault.sanitize(text, findings=combined)

    def pack(
        self,
        root_dir: str | Path,
        *,
        proprietary_terms: Sequence[str] | None = None,
        max_file_bytes: int | None = None,
        max_tokens: int | None = None,
        case_insensitive_terms: bool | None = None,
    ) -> PackResult:
        """Scan *root_dir* and return a sanitized :class:`PackResult`."""
        assert self.vault is not None
        assert self.file_filter is not None

        root = Path(root_dir).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Directory does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {root}")

        active_terms = (
            self.proprietary_terms
            if proprietary_terms is None
            else self._normalize_terms(proprietary_terms)
        )
        effective_max_bytes = (
            self.max_file_bytes if max_file_bytes is None else max_file_bytes
        )
        effective_max_tokens = (
            self.max_tokens if max_tokens is None else max_tokens
        )
        effective_case_insensitive = (
            self.case_insensitive_terms
            if case_insensitive_terms is None
            else case_insensitive_terms
        )
        gitignore_rules = _parse_gitignore(root / ".gitignore")

        included_files: list[str] = []
        blocked_files: list[str] = []
        blocked_reasons: dict[str, str] = {}
        sanitized_entries: list[tuple[str, str]] = []

        for dirpath, dirnames, filenames in os.walk(root):
            current_dir = Path(dirpath)
            rel_dir = current_dir.relative_to(root)

            # Prune technical directories and gitignored directories deterministically.
            kept_dirs: list[str] = []
            for dirname in sorted(dirnames):
                if dirname in TECHNICAL_DIRS:
                    continue
                rel_child_dir = (
                    dirname
                    if rel_dir == Path(".")
                    else f"{rel_dir.as_posix()}/{dirname}"
                )
                if _is_gitignored(rel_child_dir, gitignore_rules, is_dir=True):
                    continue
                kept_dirs.append(dirname)
            dirnames[:] = kept_dirs

            for filename in sorted(filenames):
                file_path = current_dir / filename
                rel_posix = file_path.relative_to(root).as_posix()

                if _is_gitignored(rel_posix, gitignore_rules, is_dir=False):
                    continue

                lock_pattern = _matches_lockfile_or_minified(rel_posix)
                if lock_pattern is not None:
                    blocked_files.append(rel_posix)
                    blocked_reasons[rel_posix] = (
                        f"Blocked lockfile/minified pattern '{lock_pattern}'"
                    )
                    continue

                decision = self.file_filter.check_path(file_path)
                if not decision.allowed:
                    blocked_files.append(rel_posix)
                    blocked_reasons[rel_posix] = decision.reason
                    continue

                if effective_max_bytes is not None and effective_max_bytes > 0:
                    try:
                        file_size = file_path.stat().st_size
                    except OSError as exc:
                        blocked_files.append(rel_posix)
                        blocked_reasons[rel_posix] = (
                            f"Blocked: unable to stat file ({exc})"
                        )
                        continue
                    if file_size > effective_max_bytes:
                        blocked_files.append(rel_posix)
                        blocked_reasons[rel_posix] = (
                            f"Blocked: file size {file_size} bytes exceeds max_file_bytes ({effective_max_bytes})"
                        )
                        continue

                try:
                    raw_content = file_path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError) as exc:
                    blocked_files.append(rel_posix)
                    blocked_reasons[rel_posix] = f"Blocked: non-UTF-8 or unreadable file ({exc})"
                    continue

                sanitized_content = self._sanitize_content(
                    raw_content,
                    active_terms,
                    case_insensitive=effective_case_insensitive,
                )

                if effective_max_tokens is not None:
                    candidate_files = [*included_files, rel_posix]
                    candidate_entries = [*sanitized_entries, (rel_posix, sanitized_content)]
                    candidate_bundle = self._format_bundle(candidate_files, candidate_entries)
                    candidate_tokens = len(candidate_bundle) // 4
                    if candidate_tokens > effective_max_tokens:
                        blocked_files.append(rel_posix)
                        blocked_reasons[rel_posix] = (
                            f"Blocked: adding file would exceed max_tokens ({candidate_tokens} > {effective_max_tokens})"
                        )
                        continue

                included_files.append(rel_posix)
                sanitized_entries.append((rel_posix, sanitized_content))

        bundle = self._format_bundle(included_files, sanitized_entries)
        return PackResult(
            bundle=bundle,
            included_files=included_files,
            blocked_files=blocked_files,
            included_count=len(included_files),
            blocked_count=len(blocked_files),
            estimated_tokens=len(bundle) // 4,
            vault=self.vault,
            blocked_reasons=blocked_reasons,
        )

    @staticmethod
    def _format_bundle(
        included_files: Sequence[str],
        sanitized_entries: Sequence[tuple[str, str]],
    ) -> str:
        """Assemble the LLM-ready Markdown bundle with file tree and code blocks."""
        tree_text = _render_file_tree(included_files)
        sections: list[str] = [
            "# Repository Context Bundle",
            "",
            "## File Tree",
            "",
            "```text",
            tree_text,
            "```",
            "",
            "## Files",
        ]

        if not sanitized_entries:
            sections.extend(["", "_No files included._"])
            return "\n".join(sections) + "\n"

        for rel_posix, sanitized_content in sanitized_entries:
            fence = _fence_for_content(sanitized_content)
            lang = _language_for_path(rel_posix)
            body = sanitized_content.rstrip("\n")
            sections.extend(
                [
                    "",
                    f"### `{rel_posix}`",
                    "",
                    f"{fence}{lang}",
                    body,
                    fence,
                ]
            )

        return "\n".join(sections) + "\n"
