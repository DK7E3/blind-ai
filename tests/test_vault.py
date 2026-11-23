"""Unit tests and Hypothesis H3 validation for PseudonymVault (Layer 3)."""

import ast
from pathlib import Path
import re
import sys
import tempfile
import unittest

_SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from blind_ai.core.scanner import Finding
from blind_ai.core.vault import PseudonymVault

_PLACEHOLDER_RE = re.compile(r"^__BLIND_[A-Z0-9_]+_\d+__$")
_FORBIDDEN_PLACEHOLDER_CHARS = ("'", '"', "\\", "{", "}", "\n", "\r")


class TestPseudonymVaultDeterminismAndIsolation(unittest.TestCase):
    """Tests intra-session determinism, placeholder safety, and session isolation."""

    def test_intra_session_determinism_and_safe_placeholder_format(self) -> None:
        vault = PseudonymVault(session_id="session-alpha")
        aws_key_1 = "AKIAFAKE0000EXAMPLE1"
        aws_key_2 = "AKIAFAKE0000EXAMPLE2"
        text = f"PRIMARY={aws_key_1}\nBACKUP={aws_key_2}\nMIRROR={aws_key_1}\n"

        sanitized = vault.sanitize(text)
        self.assertNotIn(aws_key_1, sanitized)
        self.assertNotIn(aws_key_2, sanitized)

        ph_1 = vault.value_to_placeholder[aws_key_1]
        ph_2 = vault.value_to_placeholder[aws_key_2]
        self.assertNotEqual(ph_1, ph_2)
        self.assertEqual(ph_1, "__BLIND_AWS_ACCESS_KEY_001__")
        self.assertEqual(ph_2, "__BLIND_AWS_ACCESS_KEY_002__")

        for placeholder in (ph_1, ph_2):
            self.assertRegex(placeholder, _PLACEHOLDER_RE)
            for forbidden in _FORBIDDEN_PLACEHOLDER_CHARS:
                self.assertNotIn(forbidden, placeholder)

        # Reusing the same secret in a subsequent call yields the exact same placeholder.
        second_sanitized = vault.sanitize(f"REUSED={aws_key_1}\n")
        self.assertEqual(second_sanitized, f"REUSED={ph_1}\n")
        self.assertEqual(sanitized, f"PRIMARY={ph_1}\nBACKUP={ph_2}\nMIRROR={ph_1}\n")
        self.assertEqual(vault.restore(sanitized), text)

    def test_session_isolation_between_vault_instances(self) -> None:
        vault_a = PseudonymVault(session_id="session-a")
        vault_b = PseudonymVault(session_id="session-b")
        self.assertNotEqual(vault_a.session_id, vault_b.session_id)

        secret_a = "AKIAFAKE0000EXAMPLE1"
        secret_b = "AKIAFAKE0000EXAMPLE9"

        sanitized_a = vault_a.sanitize(f"KEY={secret_a}\n")
        sanitized_b = vault_b.sanitize(f"KEY={secret_b}\n")

        # Each session starts its own sequence at 001 independently.
        self.assertEqual(sanitized_a, "KEY=__BLIND_AWS_ACCESS_KEY_001__\n")
        self.assertEqual(sanitized_b, "KEY=__BLIND_AWS_ACCESS_KEY_001__\n")

        self.assertEqual(vault_a.restore(sanitized_a), f"KEY={secret_a}\n")
        self.assertEqual(vault_b.restore(sanitized_b), f"KEY={secret_b}\n")
        self.assertNotIn(secret_a, vault_b.value_to_placeholder)
        self.assertNotIn(secret_b, vault_a.value_to_placeholder)

    def test_default_session_ids_are_unique(self) -> None:
        vault_1 = PseudonymVault()
        vault_2 = PseudonymVault()
        self.assertTrue(vault_1.session_id)
        self.assertTrue(vault_2.session_id)
        self.assertNotEqual(vault_1.session_id, vault_2.session_id)


class TestPseudonymVaultRoundTripAndRestore(unittest.TestCase):
    """Tests exact round-trip invariants and single-pass restore semantics."""

    def test_exact_round_trip_with_repeated_secrets_ips_and_paths(self) -> None:
        vault = PseudonymVault(session_id="roundtrip-session")
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJmYWtlLXVzZXItMDAxIiwicm9sZSI6InRlc3QifQ."
            "fakeSignaturePayload0000111122223333"
        )
        original = (
            "AWS_KEY='AKIAFAKE0000EXAMPLE1'\n"
            "AWS_DUP='AKIAFAKE0000EXAMPLE1'\n"
            'OPENAI_KEY="sk-proj-fake0000example1111token2222abcd3333efgh4444"\n'
            'GITHUB_KEY="ghp_FakeExampleToken00001111222233334444"\n'
            f'JWT_TOKEN="{jwt_token}"\n'
            "PRIVATE_IPS=['10.24.108.42', '192.168.144.27', '10.24.108.42']\n"
            "UNIX_PATH='/srv/internal/acme-fictional/secrets/prod-billing.pem'\n"
            r"WIN_PATH=r'C:\internal\corp-vault\staging\ledger.key'" + "\n"
            'WIN_ESCAPED="C:\\\\internal\\\\corp-vault\\\\staging\\\\ledger.key"\n'
        )

        sanitized = vault.sanitize(original)
        self.assertNotEqual(sanitized, original)
        for sensitive in (
            "AKIAFAKE0000EXAMPLE1",
            "sk-proj-fake0000example1111token2222abcd3333efgh4444",
            "ghp_FakeExampleToken00001111222233334444",
            jwt_token,
            "10.24.108.42",
            "192.168.144.27",
            "/srv/internal/acme-fictional/secrets/prod-billing.pem",
            r"C:\internal\corp-vault\staging\ledger.key",
        ):
            self.assertNotIn(sensitive, sanitized)

        restored = vault.restore(sanitized)
        self.assertEqual(restored, original)

    def test_empty_and_clean_text_pass_through_unchanged(self) -> None:
        vault = PseudonymVault(session_id="clean-session")
        self.assertEqual(vault.sanitize(""), "")
        self.assertEqual(vault.restore(""), "")

        clean = 'DOCS = "https://docs.example.org/guide"\nDNS = "8.8.8.8"\n'
        self.assertEqual(vault.sanitize(clean), clean)
        self.assertEqual(vault.restore(clean), clean)
        self.assertEqual(vault.value_to_placeholder, {})

    def test_sanitize_accepts_explicit_findings(self) -> None:
        vault = PseudonymVault(session_id="explicit-findings")
        text = "alpha=CUSTOM_SECRET_VALUE beta=CUSTOM_SECRET_VALUE"
        first_start = text.index("CUSTOM_SECRET_VALUE")
        second_start = text.rindex("CUSTOM_SECRET_VALUE")
        findings = [
            Finding(
                kind="custom_secret",
                value="CUSTOM_SECRET_VALUE",
                start=first_start,
                end=first_start + len("CUSTOM_SECRET_VALUE"),
                line=1,
                source="custom",
                confidence=1.0,
            ),
            Finding(
                kind="custom_secret",
                value="CUSTOM_SECRET_VALUE",
                start=second_start,
                end=second_start + len("CUSTOM_SECRET_VALUE"),
                line=1,
                source="custom",
                confidence=1.0,
            ),
        ]

        sanitized = vault.sanitize(text, findings=findings)
        self.assertEqual(
            sanitized,
            "alpha=__BLIND_CUSTOM_SECRET_001__ beta=__BLIND_CUSTOM_SECRET_001__",
        )
        self.assertEqual(vault.restore(sanitized), text)

    def test_restore_single_pass_prevents_cascading_and_prefix_collisions(self) -> None:
        # Value A contains Placeholder B literally; single-pass restore must NOT
        # re-substitute Placeholder B inside restored Value A.
        vault = PseudonymVault.from_dict(
            {
                "session_id": "collision-guard",
                "value_to_placeholder": {
                    "contains __BLIND_TOKEN_10__": "__BLIND_TOKEN_1__",
                    "SHOULD_NOT_APPEAR_INSIDE_A": "__BLIND_TOKEN_10__",
                    "SHORT_VAL": "__BLIND_KEY_1",
                    "LONG_VAL": "__BLIND_KEY_10",
                },
                "placeholder_to_value": {
                    "__BLIND_TOKEN_1__": "contains __BLIND_TOKEN_10__",
                    "__BLIND_TOKEN_10__": "SHOULD_NOT_APPEAR_INSIDE_A",
                    "__BLIND_KEY_1": "SHORT_VAL",
                    "__BLIND_KEY_10": "LONG_VAL",
                },
                "counters": {"TOKEN": 10, "KEY": 10},
            }
        )

        text = "first=__BLIND_TOKEN_1__ second=__BLIND_KEY_10 third=__BLIND_KEY_1"
        restored = vault.restore(text)
        self.assertEqual(
            restored,
            "first=contains __BLIND_TOKEN_10__ second=LONG_VAL third=SHORT_VAL",
        )


class TestPseudonymVaultSerialization(unittest.TestCase):
    """Tests JSON serialization via to_dict/from_dict and save/load."""

    def test_to_dict_from_dict_and_save_load_round_trip(self) -> None:
        vault = PseudonymVault(session_id="persist-session-42")
        original = (
            'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n'
            'HOST = "10.24.108.42"\n'
        )
        sanitized = vault.sanitize(original)

        payload = vault.to_dict()
        rehydrated = PseudonymVault.from_dict(payload)
        self.assertEqual(rehydrated.session_id, "persist-session-42")
        self.assertEqual(rehydrated.value_to_placeholder, vault.value_to_placeholder)
        self.assertEqual(rehydrated.placeholder_to_value, vault.placeholder_to_value)
        self.assertEqual(rehydrated.restore(sanitized), original)

        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_path = Path(tmp_dir) / "nested" / "vault.json"
            saved_path = vault.save(vault_path)
            self.assertEqual(saved_path, vault_path)
            self.assertTrue(vault_path.is_file())

            loaded = PseudonymVault.load(vault_path)
            self.assertEqual(loaded.session_id, vault.session_id)
            self.assertEqual(loaded.restore(sanitized), original)

            # Reuses existing placeholder and increments counter without collision.
            follow_up = (
                'OLD_AWS = "AKIAFAKE0000EXAMPLE1"\n'
                'NEW_AWS = "AKIAFAKE0000EXAMPLE2"\n'
            )
            follow_up_sanitized = loaded.sanitize(follow_up)
            self.assertIn("__BLIND_AWS_ACCESS_KEY_001__", follow_up_sanitized)
            self.assertIn("__BLIND_AWS_ACCESS_KEY_002__", follow_up_sanitized)
            self.assertEqual(loaded.restore(follow_up_sanitized), follow_up)

    def test_from_dict_rejects_inconsistent_bidirectional_mapping(self) -> None:
        with self.assertRaises(ValueError):
            PseudonymVault.from_dict(
                {
                    "session_id": "bad-session",
                    "value_to_placeholder": {"secret_a": "__BLIND_AWS_001__"},
                    "placeholder_to_value": {"__BLIND_AWS_001__": "secret_b"},
                }
            )


class TestHypothesisH3PythonASTValidity(unittest.TestCase):
    """Validates Hypothesis H3: sanitized and restored Python code both pass ast.parse()."""

    def test_h3_sanitized_and_restored_python_code_pass_ast_parse(self) -> None:
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJmYWtlLXVzZXItMDAxIiwicm9sZSI6ImFkbWluIn0."
            "fakeSignaturePayload0000111122223333"
        )
        source_code = (
            '"""Integration fixture for Hypothesis H3 AST preservation."""\n'
            "\n"
            "# Primary AWS fallback: AKIAFAKE0000EXAMPLE1 on 192.168.144.27\n"
            'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n'
            'OPENAI_API_KEY: str = "sk-proj-fake0000example1111token2222abcd3333efgh4444"\n'
            'SERVICE_SECRET = "Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6"\n'
            "\n"
            "CONFIG = {\n"
            '    "aws": "AKIAFAKE0000EXAMPLE1",\n'
            '    "github": "ghp_FakeExampleToken00001111222233334444",\n'
            f'    "jwt": "{jwt_token}",\n'
            '    "internal_host": "10.24.108.42",\n'
            '    "unix_cert": "/srv/internal/acme-fictional/secrets/prod-billing.pem",\n'
            '    "win_ledger": "C:\\\\internal\\\\corp-vault\\\\staging\\\\ledger.key",\n'
            "}\n"
            "\n"
            "def build_headers(env: str) -> dict[str, str]:\n"
            '    # Secondary token: ghp_FakeExampleToken00001111222233334444\n'
            '    endpoint = f"http://10.24.108.42:8080/{env}/sync?key=AKIAFAKE0000EXAMPLE1"\n'
            '    auth = f"Bearer sk-proj-fake0000example1111token2222abcd3333efgh4444"\n'
            '    return {"X-Endpoint": endpoint, "Authorization": auth}\n'
        )

        # Sanity check: original code is valid Python.
        ast.parse(source_code)

        vault = PseudonymVault(session_id="h3-ast-validation")
        sanitized_code = vault.sanitize(source_code)

        # Ensure every sensitive entity was removed from sanitized code.
        for sensitive in (
            "AKIAFAKE0000EXAMPLE1",
            "sk-proj-fake0000example1111token2222abcd3333efgh4444",
            "Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6",
            "ghp_FakeExampleToken00001111222233334444",
            jwt_token,
            "10.24.108.42",
            "192.168.144.27",
            "/srv/internal/acme-fictional/secrets/prod-billing.pem",
            "C:\\\\internal\\\\corp-vault\\\\staging\\\\ledger.key",
        ):
            self.assertNotIn(sensitive, sanitized_code)

        # Hypothesis H3: sanitized Python code must parse cleanly with ast.parse().
        sanitized_tree = ast.parse(sanitized_code)
        self.assertIsInstance(sanitized_tree, ast.Module)

        # Exact round-trip restoration and AST validity on restored code.
        restored_code = vault.restore(sanitized_code)
        self.assertEqual(restored_code, source_code)
        restored_tree = ast.parse(restored_code)
        self.assertIsInstance(restored_tree, ast.Module)


if __name__ == "__main__":
    unittest.main()
