"""Unit tests for Layer 3 ContextPacker and PackResult."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from blind_ai.core.contextual import HybridScanner
from blind_ai.core.packer import ContextPacker, PackResult
from blind_ai.core.vault import PseudonymVault


class ContextPackerTests(unittest.TestCase):
    def _write_file(self, root: Path, rel_path: str, content: str) -> Path:
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def _write_bytes(self, root: Path, rel_path: str, payload: bytes) -> Path:
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target

    def test_respects_gitignore_technical_dirs_and_file_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_file(
                root,
                ".gitignore",
                (
                    "# Ignore logs and build artifacts\n"
                    "\n"
                    "*.log\n"
                    "!keep.log\n"
                    "build/\n"
                    "/root_only.txt\n"
                    "docs/drafts/*.md\n"
                ),
            )
            # Included source files
            self._write_file(root, "src/app.py", "def greet() -> str:\n    return 'hello'\n")
            self._write_file(root, "keep.log", "kept log line\n")
            self._write_file(root, "nested/root_only.txt", "nested copy stays included\n")

            # Ignored by .gitignore
            self._write_file(root, "debug.log", "ignored log\n")
            self._write_file(root, "build/output.py", "ignored build artifact\n")
            self._write_file(root, "root_only.txt", "ignored root file\n")
            self._write_file(root, "docs/drafts/wip.md", "ignored draft\n")

            # Ignored technical directories
            self._write_file(root, ".git/config", "[core]\n\trepositoryformatversion = 0\n")
            self._write_file(root, ".venv/lib/site.py", "venv_code = True\n")
            self._write_file(root, "__pycache__/app.cpython-312.pyc", "cached\n")
            self._write_file(root, "node_modules/pkg/index.js", "module.exports = 1;\n")

            # Blocked by FileFilter or non-UTF-8
            self._write_file(root, ".env", "API_KEY=AKIAIOSFODNN7EXAMPLE\n")
            self._write_file(root, "certs/server.key", "PRIVATE KEY MATERIAL\n")
            self._write_file(root, "certs/root.pem", "-----BEGIN CERTIFICATE-----\n")
            self._write_bytes(root, "assets/blob.dat", b"HEADER\x00\x01\x02BINARY")
            self._write_bytes(root, "data/invalid_utf8.txt", b"\xff\xfe\x80\x81")

            packer = ContextPacker()
            result = packer.pack(root)

            self.assertIsInstance(result, PackResult)
            self.assertEqual(
                result.included_files,
                [".gitignore", "keep.log", "nested/root_only.txt", "src/app.py"],
            )
            self.assertEqual(result.included_count, 4)

            self.assertEqual(
                result.blocked_files,
                [
                    ".env",
                    "assets/blob.dat",
                    "certs/root.pem",
                    "certs/server.key",
                    "data/invalid_utf8.txt",
                ],
            )
            self.assertEqual(result.blocked_count, 5)
            for blocked_path in result.blocked_files:
                self.assertIn(blocked_path, result.blocked_reasons)

            # Technical dirs and gitignored files must not appear in bundle
            for excluded in (
                ".git/config",
                ".venv/lib/site.py",
                "__pycache__",
                "node_modules",
                "debug.log",
                "build/output.py",
                "docs/drafts/wip.md",
                "PRIVATE KEY MATERIAL",
                "AKIAIOSFODNN7EXAMPLE",
            ):
                self.assertNotIn(excluded, result.bundle)

    def test_shared_vault_cross_file_consistency_and_zero_leaks(self) -> None:
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        private_ip = "10.24.88.12"
        openai_key = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_file(
                root,
                "a_config.py",
                (
                    f'AWS_KEY = "{aws_key}"\n'
                    f'DB_HOST = "{private_ip}"\n'
                    f'OPENAI_KEY = "{openai_key}"\n'
                ),
            )
            self._write_file(
                root,
                "b_worker.py",
                (
                    f'BACKUP_AWS = "{aws_key}"\n'
                    f'REPLICA_HOST = "{private_ip}"\n'
                    f'CLIENT_KEY = "{openai_key}"\n'
                ),
            )

            shared_vault = PseudonymVault(session_id="pack-session-01")
            packer = ContextPacker(vault=shared_vault)
            result = packer.pack(root)

            self.assertIs(result.vault, shared_vault)
            self.assertEqual(result.included_count, 2)
            self.assertEqual(result.blocked_count, 0)

            # Zero leaks of raw secrets
            for secret in (aws_key, private_ip, openai_key):
                self.assertNotIn(secret, result.bundle)

            # Same placeholder reused across both files
            aws_ph = shared_vault.value_to_placeholder[aws_key]
            ip_ph = shared_vault.value_to_placeholder[private_ip]
            openai_ph = shared_vault.value_to_placeholder[openai_key]

            self.assertEqual(result.bundle.count(aws_ph), 2)
            self.assertEqual(result.bundle.count(ip_ph), 2)
            self.assertEqual(result.bundle.count(openai_ph), 2)

            # Reversible restoration
            restored = result.vault.restore(result.bundle)
            self.assertEqual(restored.count(aws_key), 2)
            self.assertEqual(restored.count(private_ip), 2)
            self.assertEqual(restored.count(openai_key), 2)

    def test_proprietary_terms_priority_reversibility_and_no_scanner_overlap(self) -> None:
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_file(
                root,
                "module_a.py",
                (
                    "# ProjectOrionCore integrates with ProjectOrion\n"
                    f'TOKEN = "{aws_key}"\n'
                    'CLIENT = "AcmeQuantum"\n'
                ),
            )
            self._write_file(
                root,
                "module_b.py",
                (
                    "# Reuse ProjectOrion and AcmeQuantum here\n"
                    'ENGINE = "ProjectOrionCore"\n'
                ),
            )

            packer = ContextPacker(
                proprietary_terms=[
                    "ProjectOrion",
                    "ProjectOrionCore",
                    "AcmeQuantum",
                    "AKIAIOSFODNN7",  # Substring of AWS key — must not break scanner finding
                ]
            )
            result = packer.pack(root)

            # Zero leaks of proprietary terms or AWS key
            for sensitive in ("ProjectOrionCore", "ProjectOrion", "AcmeQuantum", aws_key):
                self.assertNotIn(sensitive, result.bundle)

            mapping = result.vault.value_to_placeholder
            self.assertIn("ProjectOrionCore", mapping)
            self.assertIn("ProjectOrion", mapping)
            self.assertIn("AcmeQuantum", mapping)
            self.assertIn(aws_key, mapping)

            for term in ("ProjectOrionCore", "ProjectOrion", "AcmeQuantum"):
                placeholder = mapping[term]
                self.assertRegex(placeholder, r"^__BLIND_PROPRIETARY_TERM_\d{3}__$")
                # Appears once in module_a.py and once in module_b.py
                self.assertEqual(result.bundle.count(placeholder), 2)

            # Scanner finding for AWS key was preserved intact
            self.assertRegex(mapping[aws_key], r"^__BLIND_AWS_ACCESS_KEY_\d{3}__$")

            # Full restoration recovers every original term and secret
            restored = result.vault.restore(result.bundle)
            self.assertEqual(restored.count("ProjectOrionCore"), 2)
            self.assertEqual(restored.count("AcmeQuantum"), 2)
            self.assertIn(aws_key, restored)

    def test_bundle_format_tree_posix_paths_and_token_estimate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_file(root, "README.md", "# Docs\n\n```python\nprint(1)\n```\n")
            self._write_file(root, "pkg/sub/helper.py", "VALUE = 42\n")

            packer = ContextPacker()
            result = packer.pack(root)

            self.assertIn("## File Tree", result.bundle)
            self.assertIn("## Files", result.bundle)
            self.assertIn("### `README.md`", result.bundle)
            self.assertIn("### `pkg/sub/helper.py`", result.bundle)
            self.assertIn("pkg/", result.bundle)
            self.assertIn("helper.py", result.bundle)
            # Dynamic fence handles triple backticks inside README.md
            self.assertIn("````markdown", result.bundle)
            self.assertEqual(result.estimated_tokens, len(result.bundle) // 4)
            self.assertGreater(result.estimated_tokens, 0)

    def test_works_with_hybrid_scanner_for_contextual_comment_secrets(self) -> None:
        contextual_secret = "WinterFictionalPass!2026"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_file(
                root,
                "runbook.py",
                f"# Emergency staging password: {contextual_secret}\nx = 1\n",
            )

            packer = ContextPacker(scanner=HybridScanner())
            result = packer.pack(root)

            self.assertNotIn(contextual_secret, result.bundle)
            self.assertIn(contextual_secret, result.vault.restore(result.bundle))

    def test_empty_directory_and_invalid_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packer = ContextPacker()

            empty_result = packer.pack(root)
            self.assertEqual(empty_result.included_count, 0)
            self.assertEqual(empty_result.blocked_count, 0)
            self.assertEqual(empty_result.included_files, [])
            self.assertEqual(empty_result.blocked_files, [])
            self.assertEqual(empty_result.estimated_tokens, len(empty_result.bundle) // 4)

            missing = root / "does_not_exist"
            with self.assertRaises(FileNotFoundError):
                packer.pack(missing)

            regular_file = self._write_file(root, "single.txt", "hello\n")
            with self.assertRaises(NotADirectoryError):
                packer.pack(regular_file)


if __name__ == "__main__":
    unittest.main()
