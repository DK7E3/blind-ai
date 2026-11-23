"""Local reversible pseudonymization vault for Blind AI (Layer 3).

Uses only the Python 3.12 standard library. Replaces sensitive entities detected
by :class:`~blind_ai.core.scanner.DeterministicScanner` with deterministic,
syntax-safe session placeholders and restores them in a single pass.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any
import uuid

from blind_ai.core.scanner import DeterministicScanner, Finding

_KIND_SANITIZE_RE = re.compile(r"[^A-Za-z0-9]+")


def _normalize_kind(kind: str) -> str:
    """Normalize a finding kind into an uppercase identifier safe for placeholders."""
    cleaned = _KIND_SANITIZE_RE.sub("_", kind).strip("_").upper()
    return cleaned or "SECRET"


class PseudonymVault:
    """Session-scoped reversible pseudonymization vault.

    Maps sensitive values to deterministic placeholders of the form
    ``__BLIND_<KIND>_<SEQ>__`` containing only ASCII letters, digits, and
    underscores so Python string literals, f-strings, dicts, and comments
    remain syntactically valid after sanitization.
    """

    def __init__(
        self,
        session_id: str | None = None,
        *,
        scanner: DeterministicScanner | None = None,
        tag_placeholders: bool = False,
        tag_secret: str | None = None,
    ) -> None:
        self._session_id: str = session_id if session_id is not None else uuid.uuid4().hex
        self._scanner: DeterministicScanner = scanner if scanner is not None else DeterministicScanner()
        self._tag_placeholders: bool = bool(tag_placeholders or tag_secret)
        self._tag_secret: str = (
            tag_secret
            if isinstance(tag_secret, str) and tag_secret
            else secrets.token_hex(16)
        )
        self._value_to_placeholder: dict[str, str] = {}
        self._placeholder_to_value: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._restore_pattern: re.Pattern[str] | None = None

    @property
    def session_id(self) -> str:
        """Return the unique session identifier for this vault instance."""
        return self._session_id

    @property
    def value_to_placeholder(self) -> dict[str, str]:
        """Return a shallow copy of the value-to-placeholder mapping."""
        return dict(self._value_to_placeholder)

    @property
    def placeholder_to_value(self) -> dict[str, str]:
        """Return a shallow copy of the placeholder-to-value mapping."""
        return dict(self._placeholder_to_value)

    def get_or_create_placeholder(self, value: str, kind: str) -> str:
        """Return the deterministic session placeholder for *value*, creating one if needed."""
        existing = self._value_to_placeholder.get(value)
        if existing is not None:
            return existing

        normalized_kind = _normalize_kind(kind)
        seq = self._counters.get(normalized_kind, 0) + 1
        placeholder = self._format_placeholder(normalized_kind, seq, value)
        while placeholder in self._placeholder_to_value:
            seq += 1
            placeholder = self._format_placeholder(normalized_kind, seq, value)

        self._counters[normalized_kind] = seq
        self._value_to_placeholder[value] = placeholder
        self._placeholder_to_value[placeholder] = value
        self._restore_pattern = None
        return placeholder

    def _format_placeholder(self, normalized_kind: str, seq: int, value: str) -> str:
        if not self._tag_placeholders:
            return f"__BLIND_{normalized_kind}_{seq:03d}__"
        tag = hmac.new(
            self._tag_secret.encode("utf-8"),
            f"{self._session_id}:{normalized_kind}:{seq}:{value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:6].upper()
        return f"__BLIND_{normalized_kind}_{seq:03d}_{tag}__"

    def sanitize(self, text: str, findings: list[Finding] | None = None) -> str:
        """Replace detected sensitive spans in *text* with session placeholders.

        Substitutions are applied in reverse span order to preserve character
        offsets as well as surrounding quotes and delimiters.
        """
        if not text:
            return text

        active_findings: Sequence[Finding] = (
            self._scanner.scan_text(text) if findings is None else findings
        )
        if not active_findings:
            return text

        disjoint_findings = self._select_disjoint_findings(text, active_findings)
        if not disjoint_findings:
            return text

        # Assign placeholders in forward reading order for deterministic numbering.
        replacements: list[tuple[int, int, str]] = []
        for finding in disjoint_findings:
            raw_value = text[finding.start : finding.end]
            if raw_value in self._placeholder_to_value:
                continue
            placeholder = self.get_or_create_placeholder(raw_value, finding.kind)
            replacements.append((finding.start, finding.end, placeholder))

        if not replacements:
            return text

        # Apply replacements in reverse offset order to preserve span indices.
        sanitized = text
        for start, end, placeholder in reversed(replacements):
            sanitized = f"{sanitized[:start]}{placeholder}{sanitized[end:]}"
        return sanitized

    def restore(
        self,
        text: str,
        *,
        allowed_placeholders: Collection[str] | None = None,
    ) -> str:
        """Restore session placeholders in *text* back to their original values.

        When *allowed_placeholders* is provided, only placeholders explicitly in
        that collection are restored (preventing cross-context oracle extraction
        of other secrets stored in the same session vault).
        """
        if not text or not self._placeholder_to_value:
            return text

        allowed_set = (
            set(allowed_placeholders) if allowed_placeholders is not None else None
        )
        pattern = self._get_restore_pattern()

        def _replace(match: re.Match[str]) -> str:
            ph = match.group(0)
            if allowed_set is not None and ph not in allowed_set:
                return ph
            return self._placeholder_to_value[ph]

        return pattern.sub(_replace, text)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the vault state to a JSON-compatible dictionary."""
        return {
            "session_id": self._session_id,
            "value_to_placeholder": dict(self._value_to_placeholder),
            "placeholder_to_value": dict(self._placeholder_to_value),
            "counters": dict(self._counters),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        scanner: DeterministicScanner | None = None,
    ) -> PseudonymVault:
        """Reconstruct a :class:`PseudonymVault` from a dictionary created by :meth:`to_dict`."""
        session_id = data.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("Serialized vault must contain a non-empty string 'session_id'.")

        vault = cls(session_id=session_id, scanner=scanner)

        raw_v2p = data.get("value_to_placeholder")
        raw_p2v = data.get("placeholder_to_value")

        if raw_v2p is not None and not isinstance(raw_v2p, Mapping):
            raise ValueError("'value_to_placeholder' must be a mapping.")
        if raw_p2v is not None and not isinstance(raw_p2v, Mapping):
            raise ValueError("'placeholder_to_value' must be a mapping.")

        if raw_v2p is not None:
            for value, placeholder in raw_v2p.items():
                if not isinstance(value, str) or not isinstance(placeholder, str):
                    raise ValueError("Vault mappings must contain string keys and values.")
                vault._value_to_placeholder[value] = placeholder
                vault._placeholder_to_value[placeholder] = value

        if raw_p2v is not None:
            for placeholder, value in raw_p2v.items():
                if not isinstance(placeholder, str) or not isinstance(value, str):
                    raise ValueError("Vault mappings must contain string keys and values.")
                existing_val = vault._placeholder_to_value.get(placeholder)
                if existing_val is not None and existing_val != value:
                    raise ValueError(
                        f"Inconsistent bidirectional mapping for placeholder {placeholder!r}."
                    )
                vault._placeholder_to_value[placeholder] = value
                vault._value_to_placeholder[value] = placeholder

        raw_counters = data.get("counters", {})
        if not isinstance(raw_counters, Mapping):
            raise ValueError("'counters' must be a mapping.")
        for kind, count in raw_counters.items():
            if not isinstance(kind, str) or not isinstance(count, int) or isinstance(count, bool):
                raise ValueError("Vault counters must map string kinds to integers.")
            vault._counters[kind] = count

        # Ensure counters are at least as high as any serialized placeholder sequence.
        seq_pattern = re.compile(r"^__BLIND_([A-Z0-9_]+)_(\d+)__$")
        for placeholder in vault._placeholder_to_value:
            match = seq_pattern.match(placeholder)
            if match:
                kind_name = match.group(1)
                seq_num = int(match.group(2))
                if seq_num > vault._counters.get(kind_name, 0):
                    vault._counters[kind_name] = seq_num

        return vault

    def save(self, path: str | Path) -> Path:
        """Persist the vault state as UTF-8 JSON to *path* with 0600 permissions."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return target

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        scanner: DeterministicScanner | None = None,
    ) -> PseudonymVault:
        """Load a :class:`PseudonymVault` from a UTF-8 JSON file created by :meth:`save`."""
        source = Path(path)
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("Vault JSON root must be an object.")
        return cls.from_dict(data, scanner=scanner)

    def _get_restore_pattern(self) -> re.Pattern[str]:
        if self._restore_pattern is None:
            ordered = sorted(self._placeholder_to_value.keys(), key=len, reverse=True)
            self._restore_pattern = re.compile("|".join(re.escape(p) for p in ordered))
        return self._restore_pattern

    @staticmethod
    def _select_disjoint_findings(
        text: str,
        findings: Sequence[Finding],
    ) -> list[Finding]:
        text_len = len(text)
        valid = [
            f for f in findings if 0 <= f.start < f.end <= text_len
        ]
        valid.sort(key=lambda f: (f.start, -(f.end - f.start), f.kind))

        selected: list[Finding] = []
        last_end = -1
        for finding in valid:
            if finding.start < last_end:
                continue
            selected.append(finding)
            last_end = finding.end
        return selected
