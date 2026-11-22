"""Layer 1: Deterministic file filter for blocking sensitive and binary files."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import fnmatch
from pathlib import Path

BINARY_PROBE_BYTES = 1024

DEFAULT_BLOCKED_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_rsa.*",
    "secrets.*",
    "*credentials*",
    "*.p12",
    "*.pfx",
    "*.exe",
    "*.dll",
    "*.so",
    "*.bin",
    "*.pyc",
    "*.png",
    "*.jpg",
    "*.zip",
    "*.pdf",
)


@dataclass(frozen=True, slots=True)
class FilterDecision:
    """Result of evaluating a file path against the deterministic file filter."""

    allowed: bool
    reason: str
    matched_pattern: str | None = None


class FileFilter:
    """Deterministic Layer 1 filter that blocks sensitive and binary files."""

    def __init__(
        self,
        blocked_patterns: Iterable[str] | None = None,
        extra_patterns: Iterable[str] = (),
        check_binary_content: bool = True,
    ) -> None:
        base_patterns = (
            DEFAULT_BLOCKED_PATTERNS
            if blocked_patterns is None
            else tuple(blocked_patterns)
        )
        combined = (*base_patterns, *extra_patterns)
        self._blocked_patterns: tuple[str, ...] = tuple(dict.fromkeys(combined))
        self.check_binary_content: bool = check_binary_content

    @property
    def blocked_patterns(self) -> tuple[str, ...]:
        """Return the active tuple of blocked glob patterns."""
        return self._blocked_patterns

    def check_path(self, path: str | Path) -> FilterDecision:
        """Evaluate a path against blocked patterns and optional binary probing."""
        path_obj = Path(path)
        name_lower = path_obj.name.lower()
        posix_lower = path_obj.as_posix().lower()

        for pattern in self._blocked_patterns:
            normalized_pattern = pattern.replace("\\", "/").lower()
            if fnmatch.fnmatchcase(name_lower, normalized_pattern) or fnmatch.fnmatchcase(
                posix_lower, normalized_pattern
            ):
                return FilterDecision(
                    allowed=False,
                    reason=f"Blocked by pattern '{pattern}'",
                    matched_pattern=pattern,
                )

        if self.check_binary_content and path_obj.is_file():
            if self._contains_null_byte(path_obj):
                return FilterDecision(
                    allowed=False,
                    reason="Blocked due to binary content (null byte detected)",
                    matched_pattern=None,
                )

        return FilterDecision(
            allowed=True,
            reason="Allowed",
            matched_pattern=None,
        )

    def is_allowed(self, path: str | Path) -> bool:
        """Return True if the path passes the filter, False otherwise."""
        return self.check_path(path).allowed

    def filter_paths(
        self, paths: Iterable[str | Path]
    ) -> tuple[list[Path], list[FilterDecision]]:
        """Partition paths into allowed Path objects and blocked FilterDecisions."""
        allowed_paths: list[Path] = []
        blocked_decisions: list[FilterDecision] = []

        for raw_path in paths:
            path_obj = Path(raw_path)
            decision = self.check_path(path_obj)
            if decision.allowed:
                allowed_paths.append(path_obj)
            else:
                blocked_decisions.append(decision)

        return allowed_paths, blocked_decisions

    @staticmethod
    def _contains_null_byte(path_obj: Path) -> bool:
        try:
            with path_obj.open("rb") as file_handle:
                header = file_handle.read(BINARY_PROBE_BYTES)
        except OSError:
            return False
        return b"\x00" in header
