"""Authenticated encryption, TTL session management, and safe audit logging for Blind AI.

Uses only the Python 3.12 standard library. Protects :class:`PseudonymVault`
state at rest with PBKDF2-HMAC-SHA256 key derivation and Encrypt-then-MAC
(HMAC-SHA256 counter-mode keystream XOR + HMAC-SHA256 tag), manages session
lifetimes via a thread-safe TTL store, and records structured audit events
without ever persisting raw secret values.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any

from blind_ai.core.scanner import DeterministicScanner
from blind_ai.core.vault import PseudonymVault

_MAGIC = b"BLINDVLT"
_VERSION = b"\x01"
_HEADER = _MAGIC + _VERSION
_SALT_LEN = 16
_IV_LEN = 16
_TAG_LEN = 32
_KEY_LEN = 32
_PBKDF2_ITERATIONS = 200_000
_MIN_FILE_LEN = len(_HEADER) + _SALT_LEN + _IV_LEN + _TAG_LEN + 1

_PLACEHOLDER_RE = re.compile(r"^__BLIND_[A-Z0-9_]+_\d+__$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "value",
        "raw_value",
        "original",
        "original_value",
        "secret",
        "secrets",
        "plaintext",
        "passphrase",
        "password",
        "token",
        "api_key",
        "credential",
        "credentials",
        "text",
        "content",
        "payload",
    }
)


def _validate_passphrase(passphrase: str) -> bytes:
    """Validate that *passphrase* is a non-empty string and return UTF-8 bytes."""
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("Passphrase must be a non-empty string.")
    return passphrase.encode("utf-8")


def _derive_keys(passphrase_bytes: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derive 32-byte encryption and 32-byte MAC keys via PBKDF2-HMAC-SHA256."""
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase_bytes,
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_KEY_LEN * 2,
    )
    return derived[:_KEY_LEN], derived[_KEY_LEN:]


def _xor_keystream(data: bytes, enc_key: bytes, iv: bytes) -> bytes:
    """XOR *data* with a deterministic HMAC-SHA256 counter-mode keystream."""
    out = bytearray(len(data))
    block_size = 32
    for counter, offset in enumerate(range(0, len(data), block_size)):
        keystream = hmac.new(
            enc_key,
            iv + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        chunk = data[offset : offset + block_size]
        for idx, byte in enumerate(chunk):
            out[offset + idx] = byte ^ keystream[idx]
    return bytes(out)


def save_encrypted(
    vault: PseudonymVault,
    path: str | Path,
    passphrase: str,
) -> Path:
    """Serialize, encrypt, and authenticate *vault* to *path* using *passphrase*.

    Format: ``HEADER (9B) || SALT (16B) || IV (16B) || CIPHERTEXT || TAG (32B)``
    where ``TAG = HMAC-SHA256(mac_key, HEADER || SALT || IV || CIPHERTEXT)``.
    """
    if not isinstance(vault, PseudonymVault):
        raise TypeError("vault must be a PseudonymVault instance.")

    passphrase_bytes = _validate_passphrase(passphrase)
    salt = secrets.token_bytes(_SALT_LEN)
    iv = secrets.token_bytes(_IV_LEN)
    enc_key, mac_key = _derive_keys(passphrase_bytes, salt)

    plaintext = json.dumps(
        vault.to_dict(),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = _xor_keystream(plaintext, enc_key, iv)
    tag = hmac.new(
        mac_key,
        _HEADER + salt + iv + ciphertext,
        hashlib.sha256,
    ).digest()

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_HEADER + salt + iv + ciphertext + tag)
    try:
        import os as _os
        _os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def load_encrypted(
    path: str | Path,
    passphrase: str,
    *,
    scanner: DeterministicScanner | None = None,
) -> PseudonymVault:
    """Authenticate, decrypt, and reconstruct a :class:`PseudonymVault` from *path*.

    Raises :class:`ValueError` if *passphrase* is empty or wrong, or if the
    file header/version is invalid, truncated, or tampered with.
    """
    passphrase_bytes = _validate_passphrase(passphrase)
    raw = Path(path).read_bytes()

    if len(raw) < _MIN_FILE_LEN:
        raise ValueError("Encrypted vault file is truncated or malformed.")

    header = raw[: len(_HEADER)]
    if header != _HEADER:
        raise ValueError("Invalid encrypted vault header or unsupported version.")

    offset = len(_HEADER)
    salt = raw[offset : offset + _SALT_LEN]
    offset += _SALT_LEN
    iv = raw[offset : offset + _IV_LEN]
    offset += _IV_LEN
    ciphertext = raw[offset:-_TAG_LEN]
    tag = raw[-_TAG_LEN:]

    if not ciphertext:
        raise ValueError("Encrypted vault ciphertext is empty or truncated.")

    enc_key, mac_key = _derive_keys(passphrase_bytes, salt)
    expected_tag = hmac.new(
        mac_key,
        header + salt + iv + ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError(
            "Encrypted vault authentication failed: invalid passphrase or tampered data."
        )

    plaintext = _xor_keystream(ciphertext, enc_key, iv)
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Decrypted vault payload is not valid UTF-8 JSON.") from exc

    if not isinstance(data, Mapping):
        raise ValueError("Decrypted vault JSON root must be an object.")

    return PseudonymVault.from_dict(data, scanner=scanner)


class TTLSessionStore:
    """Thread-safe in-memory store of :class:`PseudonymVault` sessions with TTL expiration."""

    def __init__(
        self,
        ttl_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ValueError("ttl_seconds must be a finite number greater than 0.")
        self._ttl_seconds: float = float(ttl_seconds)
        self._clock: Callable[[], float] = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, tuple[PseudonymVault, float]] = {}

    @property
    def ttl_seconds(self) -> float:
        """Return the configured inactivity TTL in seconds."""
        return self._ttl_seconds

    def _is_expired(self, last_access: float, now: float) -> bool:
        return (now - last_access) >= self._ttl_seconds

    def get_or_create(
        self,
        session_id: str,
        *,
        scanner: DeterministicScanner | None = None,
    ) -> PseudonymVault:
        """Return an active vault for *session_id* or create a fresh one if missing/expired."""
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string.")
        with self._lock:
            now = self._clock()
            entry = self._sessions.get(session_id)
            if entry is not None:
                vault, last_access = entry
                if not self._is_expired(last_access, now):
                    self._sessions[session_id] = (vault, now)
                    return vault
                del self._sessions[session_id]

            vault = PseudonymVault(session_id=session_id, scanner=scanner)
            self._sessions[session_id] = (vault, now)
            return vault

    def get(self, session_id: str) -> PseudonymVault | None:
        """Return the vault for *session_id* if active (renewing TTL), or ``None`` if missing/expired."""
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                return None
            now = self._clock()
            vault, last_access = entry
            if self._is_expired(last_access, now):
                del self._sessions[session_id]
                return None
            self._sessions[session_id] = (vault, now)
            return vault

    def put(self, session_id: str, vault: PseudonymVault) -> None:
        """Store or replace *vault* under *session_id* and renew its last-access timestamp."""
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string.")
        if not isinstance(vault, PseudonymVault):
            raise TypeError("vault must be a PseudonymVault instance.")
        with self._lock:
            self._sessions[session_id] = (vault, self._clock())

    def delete(self, session_id: str) -> bool:
        """Remove *session_id* from the store. Return ``True`` if it existed."""
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def purge_expired(self) -> int:
        """Remove all expired sessions and return the number of purged entries."""
        with self._lock:
            now = self._clock()
            expired = [
                sid
                for sid, (_, last_access) in self._sessions.items()
                if self._is_expired(last_access, now)
            ]
            for sid in expired:
                del self._sessions[sid]
            return len(expired)

    def __len__(self) -> int:
        with self._lock:
            self.purge_expired()
            return len(self._sessions)


class AuditLogger:
    """Structured JSONL audit logger that strictly prevents secret values from being logged."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._path: Path | None = Path(path) if path is not None else None
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else lambda: datetime.now(timezone.utc)
        )
        self._lock = threading.RLock()
        self._events: list[dict[str, Any]] = []

    @property
    def path(self) -> Path | None:
        """Return the JSONL log file path, or ``None`` for in-memory-only logging."""
        return self._path

    @property
    def events(self) -> list[dict[str, Any]]:
        """Return a shallow copy of all recorded audit events in memory."""
        with self._lock:
            return [dict(item) for item in self._events]

    def log(
        self,
        event: str,
        *,
        session_id: str | None = None,
        kind: str | None = None,
        placeholder: str | None = None,
        count: int = 0,
        forbidden_values: Iterable[str] = (),
        **extra: Any,
    ) -> dict[str, Any]:
        """Record a structured audit event after verifying no raw secrets are present.

        Only the whitelisted schema fields (``timestamp``, ``event``,
        ``session_id``, ``kind``, ``placeholder``, ``count``) are persisted.
        Any extra/secret-bearing keyword argument, non-placeholder value in
        ``placeholder``, or occurrence of a string from ``forbidden_values``
        raises :class:`ValueError`.
        """
        if extra:
            forbidden_keys = sorted(
                k for k in extra if k.lower() in _FORBIDDEN_FIELD_NAMES
            )
            if forbidden_keys:
                raise ValueError(
                    f"AuditLogger rejects secret-bearing fields: {', '.join(forbidden_keys)}."
                )
            unknown_keys = sorted(extra.keys())
            raise ValueError(
                f"AuditLogger does not accept unwhitelisted fields: {', '.join(unknown_keys)}."
            )

        if not isinstance(event, str) or not _SAFE_IDENTIFIER_RE.match(event):
            raise ValueError("event must be a safe non-empty identifier string.")
        if session_id is not None and (
            not isinstance(session_id, str) or not _SAFE_IDENTIFIER_RE.match(session_id)
        ):
            raise ValueError("session_id must be None or a safe identifier string.")
        if kind is not None and (
            not isinstance(kind, str) or not _SAFE_IDENTIFIER_RE.match(kind)
        ):
            raise ValueError("kind must be None or a safe identifier string.")
        if placeholder is not None and (
            not isinstance(placeholder, str) or not _PLACEHOLDER_RE.match(placeholder)
        ):
            raise ValueError(
                "placeholder must be None or match '__BLIND_<KIND>_<SEQ>__' (never a raw secret)."
            )
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("count must be a non-negative integer.")

        record: dict[str, Any] = {
            "timestamp": self._clock().isoformat(),
            "event": event,
            "session_id": session_id,
            "kind": kind,
            "placeholder": placeholder,
            "count": count,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))

        for secret in forbidden_values:
            if isinstance(secret, str) and secret and secret in line:
                raise ValueError(
                    "Audit log entry rejected: contains a forbidden original secret value."
                )

        with self._lock:
            self._events.append(record)
            if self._path is not None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")

        return dict(record)

    def log_vault_event(
        self,
        event: str,
        vault: PseudonymVault,
        *,
        kind: str | None = None,
        placeholder: str | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """Log a vault-scoped event while automatically guarding all secrets stored in *vault*."""
        if not isinstance(vault, PseudonymVault):
            raise TypeError("vault must be a PseudonymVault instance.")
        effective_count = (
            len(vault.placeholder_to_value) if count is None else count
        )
        return self.log(
            event,
            session_id=vault.session_id,
            kind=kind,
            placeholder=placeholder,
            count=effective_count,
            forbidden_values=vault.value_to_placeholder.keys(),
        )

    def read_events(self) -> list[dict[str, Any]]:
        """Read all persisted JSONL events from disk if configured, otherwise return memory events."""
        with self._lock:
            if self._path is None:
                return [dict(item) for item in self._events]
            if not self._path.exists():
                return []
            lines = self._path.read_text(encoding="utf-8").splitlines()
            return [json.loads(line) for line in lines if line.strip()]
