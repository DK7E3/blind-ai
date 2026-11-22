"""Configuration loading (``.blindai.toml``), allowlist filtering, and custom rules.

Uses only the Python 3.12 standard library (``tomllib``, ``re``, ``dataclasses``,
``pathlib``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
import re
import tomllib
from typing import Any

from blind_ai.core.file_filter import FileFilter
from blind_ai.core.scanner import Finding

DEFAULT_CONFIG_FILENAME = ".blindai.toml"


def _dedupe_strings(values: Iterable[str]) -> tuple[str, ...]:
    """Return unique strings preserving first-seen order."""
    return tuple(dict.fromkeys(values))


def _coerce_str_list(raw: Any, *, field_name: str) -> list[str]:
    """Validate and coerce a TOML list of strings."""
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"Config field '{field_name}' must be a list of strings.")
    return list(raw)


def _coerce_custom_rules(
    raw: Any, *, field_name: str
) -> list[tuple[str, str]]:
    """Validate and coerce custom rules from a mapping or pair sequence."""
    if raw is None:
        return []
    if isinstance(raw, Mapping):
        pairs: list[tuple[str, str]] = []
        for name, pattern in raw.items():
            if not isinstance(name, str) or not isinstance(pattern, str):
                raise ValueError(
                    f"Config field '{field_name}' must map string rule names to regex strings."
                )
            pairs.append((name, pattern))
        return pairs
    if isinstance(raw, (list, tuple)):
        pairs = []
        for entry in raw:
            if (
                isinstance(entry, (list, tuple))
                and len(entry) == 2
                and isinstance(entry[0], str)
                and isinstance(entry[1], str)
            ):
                pairs.append((entry[0], entry[1]))
            else:
                raise ValueError(
                    f"Config field '{field_name}' entries must be (name, pattern) string pairs."
                )
        return pairs
    raise ValueError(
        f"Config field '{field_name}' must be a table mapping rule names to regex strings."
    )


@dataclass(frozen=True, slots=True)
class BlindAIConfig:
    """Immutable configuration loaded from ``.blindai.toml``."""

    allowlist_values: tuple[str, ...] = ()
    allowlist_patterns: tuple[str, ...] = ()
    extra_blocked_files: tuple[str, ...] = ()
    custom_rules: tuple[tuple[str, str], ...] = ()
    _compiled_allowlist_patterns: tuple[re.Pattern[str], ...] = field(
        init=False, repr=False, compare=False
    )
    _compiled_custom_rules: tuple[tuple[str, re.Pattern[str]], ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        normalized_values = _dedupe_strings(self.allowlist_values)
        normalized_patterns = _dedupe_strings(self.allowlist_patterns)
        normalized_blocked = _dedupe_strings(self.extra_blocked_files)

        if isinstance(self.custom_rules, Mapping):
            raw_rules = _coerce_custom_rules(self.custom_rules, field_name="custom_rules")
        else:
            raw_rules = _coerce_custom_rules(self.custom_rules, field_name="custom_rules")
        # Preserve last definition for duplicate rule names while keeping order.
        deduped_rules = tuple(dict(raw_rules).items())

        compiled_allowlist: list[re.Pattern[str]] = []
        for pattern in normalized_patterns:
            try:
                compiled_allowlist.append(re.compile(pattern))
            except re.error as exc:
                raise ValueError(
                    f"Invalid allowlist regex pattern {pattern!r}: {exc}"
                ) from exc

        compiled_custom: list[tuple[str, re.Pattern[str]]] = []
        for name, pattern in deduped_rules:
            try:
                compiled_custom.append((name, re.compile(pattern)))
            except re.error as exc:
                raise ValueError(
                    f"Invalid custom rule regex for {name!r} ({pattern!r}): {exc}"
                ) from exc

        object.__setattr__(self, "allowlist_values", normalized_values)
        object.__setattr__(self, "allowlist_patterns", normalized_patterns)
        object.__setattr__(self, "extra_blocked_files", normalized_blocked)
        object.__setattr__(self, "custom_rules", deduped_rules)
        object.__setattr__(
            self, "_compiled_allowlist_patterns", tuple(compiled_allowlist)
        )
        object.__setattr__(self, "_compiled_custom_rules", tuple(compiled_custom))

    @property
    def compiled_custom_rules(self) -> tuple[tuple[str, re.Pattern[str]], ...]:
        """Return compiled ``(name, pattern)`` custom regex rules."""
        return self._compiled_custom_rules

    @classmethod
    def from_toml(cls, path: str | Path) -> BlindAIConfig:
        """Load configuration from a TOML file, returning defaults if absent.

        Supports keys at the root level as well as ``[allowlist]``, ``[rules]``,
        ``[files]``, and ``[custom_rules]`` tables.
        """
        config_path = Path(path)
        if not config_path.is_file():
            return cls()

        with config_path.open("rb") as fh:
            data = tomllib.load(fh)

        if not isinstance(data, dict):
            raise ValueError("TOML configuration root must be a table.")

        allowlist_values: list[str] = []
        allowlist_patterns: list[str] = []
        extra_blocked_files: list[str] = []
        custom_rules: list[tuple[str, str]] = []

        # Root-level keys
        allowlist_values.extend(
            _coerce_str_list(data.get("allowlist_values"), field_name="allowlist_values")
        )
        allowlist_patterns.extend(
            _coerce_str_list(
                data.get("allowlist_patterns"), field_name="allowlist_patterns"
            )
        )
        extra_blocked_files.extend(
            _coerce_str_list(
                data.get("extra_blocked_files"), field_name="extra_blocked_files"
            )
        )
        custom_rules.extend(
            _coerce_custom_rules(data.get("custom_rules"), field_name="custom_rules")
        )

        # [allowlist] section
        allowlist_section = data.get("allowlist")
        if allowlist_section is not None:
            if not isinstance(allowlist_section, dict):
                raise ValueError("Config section '[allowlist]' must be a table.")
            allowlist_values.extend(
                _coerce_str_list(
                    allowlist_section.get("values"), field_name="allowlist.values"
                )
            )
            allowlist_values.extend(
                _coerce_str_list(
                    allowlist_section.get("allowlist_values"),
                    field_name="allowlist.allowlist_values",
                )
            )
            allowlist_patterns.extend(
                _coerce_str_list(
                    allowlist_section.get("patterns"), field_name="allowlist.patterns"
                )
            )
            allowlist_patterns.extend(
                _coerce_str_list(
                    allowlist_section.get("allowlist_patterns"),
                    field_name="allowlist.allowlist_patterns",
                )
            )

        # [rules] section
        rules_section = data.get("rules")
        if rules_section is not None:
            if not isinstance(rules_section, dict):
                raise ValueError("Config section '[rules]' must be a table.")
            extra_blocked_files.extend(
                _coerce_str_list(
                    rules_section.get("extra_blocked_files"),
                    field_name="rules.extra_blocked_files",
                )
            )
            custom_rules.extend(
                _coerce_custom_rules(
                    rules_section.get("custom_rules"), field_name="rules.custom_rules"
                )
            )
            for key, value in rules_section.items():
                if key in ("extra_blocked_files", "custom_rules"):
                    continue
                if isinstance(value, str):
                    custom_rules.append((key, value))
                else:
                    raise ValueError(
                        f"Config field 'rules.{key}' must be a regex pattern string."
                    )

        # Optional [files] section for extra_blocked_files
        files_section = data.get("files")
        if files_section is not None:
            if not isinstance(files_section, dict):
                raise ValueError("Config section '[files]' must be a table.")
            extra_blocked_files.extend(
                _coerce_str_list(
                    files_section.get("extra_blocked_files"),
                    field_name="files.extra_blocked_files",
                )
            )

        return cls(
            allowlist_values=tuple(allowlist_values),
            allowlist_patterns=tuple(allowlist_patterns),
            extra_blocked_files=tuple(extra_blocked_files),
            custom_rules=tuple(custom_rules),
        )

    @classmethod
    def discover(
        cls,
        start_dir: str | Path | None = None,
        *,
        filename: str = DEFAULT_CONFIG_FILENAME,
    ) -> BlindAIConfig:
        """Search *start_dir* and its parent directories for ``.blindai.toml``.

        Returns default ``BlindAIConfig()`` when no config file is found.
        """
        base = Path.cwd() if start_dir is None else Path(start_dir)
        resolved = base.resolve()
        current = resolved.parent if resolved.is_file() else resolved

        for directory in (current, *current.parents):
            candidate = directory / filename
            if candidate.is_file():
                return cls.from_toml(candidate)

        return cls()

    def is_allowlisted(self, value: str) -> bool:
        """Return True if *value* matches an allowlisted literal or regex pattern."""
        if value in self.allowlist_values:
            return True
        return any(
            pattern.search(value) is not None
            for pattern in self._compiled_allowlist_patterns
        )

    def filter_findings(self, findings: Iterable[Finding]) -> list[Finding]:
        """Remove allowlisted findings while leaving all other findings untouched."""
        return [
            finding for finding in findings if not self.is_allowlisted(finding.value)
        ]

    def build_file_filter(self, *, check_binary_content: bool = True) -> FileFilter:
        """Build a Layer 1 ``FileFilter`` augmented with ``extra_blocked_files``."""
        return FileFilter(
            extra_patterns=self.extra_blocked_files,
            check_binary_content=check_binary_content,
        )
