"""Unit tests for authenticated vault encryption, TTL session store, and safe audit logging."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest

from blind_ai.core.scanner import DeterministicScanner
from blind_ai.core.secure_vault import (
    AuditLogger,
    TTLSessionStore,
    _HEADER,
    _IV_LEN,
    _SALT_LEN,
    _TAG_LEN,
    load_encrypted,
    save_encrypted,
)
from blind_ai.core.vault import PseudonymVault


class FakeClock:
    """Deterministic controllable monotonic clock for TTL tests."""

    def __init__(self, start: float = 100.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestEncryptedVault(unittest.TestCase):
    """Tests for save_encrypted and load_encrypted."""

    def _build_sample_vault(self) -> tuple[PseudonymVault, list[str]]:
        vault = PseudonymVault(session_id="sess-secure-001")
        secrets_list = [
            "sk-live-super-secret-token-987654321",
            "alice.secret@corp.example.com",
            "123.456.789-00",
            "senha-ultra-secreta-çãé",
        ]
        vault.get_or_create_placeholder(secrets_list[0], "API_KEY")
        vault.get_or_create_placeholder(secrets_list[1], "EMAIL")
        vault.get_or_create_placeholder(secrets_list[2], "CPF")
        vault.get_or_create_placeholder(secrets_list[3], "PASSWORD")
        return vault, secrets_list

    def test_round_trip_and_no_plaintext_on_disk(self) -> None:
        vault, secrets_list = self._build_sample_vault()
        passphrase = "correct-horse-battery-staple"
        custom_scanner = DeterministicScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "nested" / "vault.enc"
            saved_path = save_encrypted(vault, vault_path, passphrase)
            self.assertEqual(saved_path, vault_path)

            raw_bytes = vault_path.read_bytes()
            self.assertTrue(raw_bytes.startswith(_HEADER))

            # None of the original secrets or session metadata may appear in plaintext on disk.
            for secret in secrets_list:
                self.assertNotIn(secret.encode("utf-8"), raw_bytes)
            self.assertNotIn(vault.session_id.encode("utf-8"), raw_bytes)
            for placeholder in vault.placeholder_to_value:
                self.assertNotIn(placeholder.encode("utf-8"), raw_bytes)

            loaded = load_encrypted(vault_path, passphrase, scanner=custom_scanner)
            self.assertEqual(loaded.session_id, vault.session_id)
            self.assertEqual(loaded.value_to_placeholder, vault.value_to_placeholder)
            self.assertEqual(loaded.placeholder_to_value, vault.placeholder_to_value)
            self.assertIs(loaded._scanner, custom_scanner)

            # Verify restore works identically after decryption.
            p0 = vault.value_to_placeholder[secrets_list[0]]
            p3 = vault.value_to_placeholder[secrets_list[3]]
            self.assertEqual(
                loaded.restore(f"key={p0}; pwd={p3}"),
                f"key={secrets_list[0]}; pwd={secrets_list[3]}",
            )

            # Saving the same vault twice uses fresh salt/iv, producing different ciphertexts.
            vault_path_2 = Path(tmpdir) / "vault2.enc"
            save_encrypted(vault, vault_path_2, passphrase)
            self.assertNotEqual(raw_bytes, vault_path_2.read_bytes())

    def test_empty_passphrase_rejected(self) -> None:
        vault, _ = self._build_sample_vault()
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "vault.enc"
            with self.assertRaises(ValueError):
                save_encrypted(vault, vault_path, "")

            save_encrypted(vault, vault_path, "valid-pass")
            with self.assertRaises(ValueError):
                load_encrypted(vault_path, "")

    def test_wrong_passphrase_raises_value_error(self) -> None:
        vault, _ = self._build_sample_vault()
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "vault.enc"
            save_encrypted(vault, vault_path, "right-passphrase")

            with self.assertRaises(ValueError):
                load_encrypted(vault_path, "wrong-passphrase")

    def test_tampering_every_section_and_truncation_raise_value_error(self) -> None:
        vault, _ = self._build_sample_vault()
        passphrase = "tamper-test-passphrase"

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "vault.enc"
            save_encrypted(vault, vault_path, passphrase)
            original = vault_path.read_bytes()

            header_end = len(_HEADER)
            salt_end = header_end + _SALT_LEN
            iv_end = salt_end + _IV_LEN
            ct_end = len(original) - _TAG_LEN

            tamper_positions = {
                "header": 0,
                "version": header_end - 1,
                "salt": header_end + 3,
                "iv": salt_end + 5,
                "ciphertext": iv_end + 7,
                "tag": ct_end + 11,
            }

            for section, index in tamper_positions.items():
                with self.subTest(section=section):
                    mutated = bytearray(original)
                    mutated[index] ^= 0x01
                    tampered_path = Path(tmpdir) / f"tampered_{section}.enc"
                    tampered_path.write_bytes(bytes(mutated))
                    with self.assertRaises(ValueError):
                        load_encrypted(tampered_path, passphrase)

            # Truncated files (various lengths including 0, header-only, missing last byte).
            for trunc_len in (0, len(_HEADER), iv_end, len(original) - 1):
                with self.subTest(trunc_len=trunc_len):
                    trunc_path = Path(tmpdir) / f"trunc_{trunc_len}.enc"
                    trunc_path.write_bytes(original[:trunc_len])
                    with self.assertRaises(ValueError):
                        load_encrypted(trunc_path, passphrase)


class TestTTLSessionStore(unittest.TestCase):
    """Tests for TTLSessionStore expiration, renewal, deletion, and thread safety."""

    def test_invalid_ttl_raises_value_error(self) -> None:
        for bad_ttl in (0, -5, float("nan"), float("inf"), True):
            with self.subTest(bad_ttl=bad_ttl):
                with self.assertRaises(ValueError):
                    TTLSessionStore(bad_ttl)

    def test_expiration_and_renewal_with_fake_clock(self) -> None:
        clock = FakeClock(start=1000.0)
        store = TTLSessionStore(ttl_seconds=30.0, clock=clock)

        v1 = store.get_or_create("s1")
        v1.get_or_create_placeholder("secret-alpha", "API_KEY")

        # Advance 20s (< 30s): get() returns same vault and renews TTL.
        clock.advance(20.0)
        self.assertIs(store.get("s1"), v1)

        # Advance another 20s (40s total, but only 20s since renewal): still active.
        clock.advance(20.0)
        self.assertIs(store.get_or_create("s1"), v1)

        # Advance exactly 30s without access: expired.
        clock.advance(30.0)
        self.assertIsNone(store.get("s1"))

        # get_or_create after expiration returns a brand-new empty vault.
        v1_new = store.get_or_create("s1")
        self.assertIsNot(v1_new, v1)
        self.assertEqual(v1_new.placeholder_to_value, {})

    def test_put_delete_and_purge_expired(self) -> None:
        clock = FakeClock(start=0.0)
        store = TTLSessionStore(ttl_seconds=10.0, clock=clock)

        v_a = PseudonymVault(session_id="a")
        v_b = PseudonymVault(session_id="b")
        store.put("a", v_a)

        clock.advance(6.0)
        store.put("b", v_b)

        # At t=11: 'a' is expired (11 >= 10), 'b' is still active (5 < 10).
        clock.advance(5.0)
        purged = store.purge_expired()
        self.assertEqual(purged, 1)
        self.assertIsNone(store.get("a"))
        self.assertIs(store.get("b"), v_b)

        # put() renews TTL for 'b'.
        clock.advance(8.0)
        store.put("b", v_b)
        clock.advance(8.0)
        self.assertIs(store.get("b"), v_b)

        # delete() removes active session.
        self.assertTrue(store.delete("b"))
        self.assertFalse(store.delete("b"))
        self.assertEqual(len(store), 0)

    def test_thread_safety_concurrent_access(self) -> None:
        store = TTLSessionStore(ttl_seconds=60.0)
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                sid = f"worker-{idx % 4}"
                for _ in range(25):
                    vault = store.get_or_create(sid)
                    store.put(sid, vault)
                    _ = store.get(sid)
                store.purge_expired()
            except Exception as exc:  # pragma: no cover - failure capture
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(store), 4)


class TestAuditLogger(unittest.TestCase):
    """Tests for AuditLogger structured JSONL output and secret-leakage prevention."""

    def test_memory_and_jsonl_file_logging_without_secrets(self) -> None:
        vault = PseudonymVault(session_id="sess-audit-1")
        raw_secret = "sk-prod-very-sensitive-99999"
        placeholder = vault.get_or_create_placeholder(raw_secret, "API_KEY")

        # In-memory mode
        mem_logger = AuditLogger()
        rec = mem_logger.log_vault_event(
            "sanitize",
            vault,
            kind="API_KEY",
            placeholder=placeholder,
        )
        self.assertEqual(
            set(rec.keys()),
            {"timestamp", "event", "session_id", "kind", "placeholder", "count"},
        )
        self.assertEqual(rec["event"], "sanitize")
        self.assertEqual(rec["session_id"], "sess-audit-1")
        self.assertEqual(rec["kind"], "API_KEY")
        self.assertEqual(rec["placeholder"], placeholder)
        self.assertEqual(rec["count"], 1)
        self.assertNotIn(raw_secret, json.dumps(mem_logger.events))

        # File JSONL mode
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "logs" / "audit.jsonl"
            file_logger = AuditLogger(path=log_path)
            file_logger.log_vault_event(
                "sanitize",
                vault,
                kind="API_KEY",
                placeholder=placeholder,
            )
            file_logger.log(
                "vault_saved",
                session_id=vault.session_id,
                count=1,
                forbidden_values=[raw_secret],
            )

            raw_text = log_path.read_text(encoding="utf-8")
            self.assertNotIn(raw_secret, raw_text)

            parsed = file_logger.read_events()
            self.assertEqual(len(parsed), 2)
            self.assertEqual(parsed[0]["placeholder"], placeholder)
            self.assertEqual(parsed[1]["event"], "vault_saved")

    def test_rejects_raw_secrets_and_forbidden_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path=log_path)

            # Raw secret passed as placeholder must be rejected.
            with self.assertRaises(ValueError):
                logger.log(
                    "sanitize",
                    session_id="sess-1",
                    kind="API_KEY",
                    placeholder="sk-live-leaked-secret",
                    count=1,
                )

            # Secret-bearing keyword arguments must be rejected.
            with self.assertRaises(ValueError):
                logger.log(
                    "sanitize",
                    session_id="sess-1",
                    value="sk-live-leaked-secret",
                )

            with self.assertRaises(ValueError):
                logger.log(
                    "sanitize",
                    session_id="sess-1",
                    passphrase="my-secret-passphrase",
                )

            # Forbidden secret value appearing in any allowed field must be rejected.
            with self.assertRaises(ValueError):
                logger.log(
                    "sanitize",
                    session_id="secret-token-123",
                    forbidden_values=["secret-token-123"],
                )

            # Nothing should have been written to memory or disk after rejected attempts.
            self.assertEqual(logger.events, [])
            self.assertFalse(log_path.exists())


if __name__ == "__main__":
    unittest.main()
