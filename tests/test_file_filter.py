"""Unit tests for Layer 1 deterministic file filter."""

from pathlib import Path
import sys
import tempfile
import unittest

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from blind_ai.core.file_filter import (  # noqa: E402
    DEFAULT_BLOCKED_PATTERNS,
    FileFilter,
    FilterDecision,
)


class TestFileFilter(unittest.TestCase):
    def setUp(self) -> None:
        self.file_filter = FileFilter()

    def test_blocks_sensitive_default_files(self) -> None:
        blocked_samples = [
            ".env",
            ".env.local",
            "app.pem",
            "api.key",
            "id_rsa",
            "id_rsa.pub",
            "secrets.json",
            "credentials.yml",
            "cert.p12",
            "cert.pfx",
        ]
        for sample in blocked_samples:
            with self.subTest(sample=sample):
                decision = self.file_filter.check_path(sample)
                self.assertIsInstance(decision, FilterDecision)
                self.assertFalse(decision.allowed)
                self.assertIsNotNone(decision.matched_pattern)
                self.assertFalse(self.file_filter.is_allowed(sample))

    def test_blocks_binary_extensions(self) -> None:
        binary_samples = [
            "tool.exe",
            "lib.dll",
            "module.so",
            "dump.bin",
            "cache.pyc",
            "logo.png",
            "photo.jpg",
            "archive.zip",
            "report.pdf",
        ]
        for sample in binary_samples:
            with self.subTest(sample=sample):
                decision = self.file_filter.check_path(sample)
                self.assertFalse(decision.allowed)
                self.assertIsNotNone(decision.matched_pattern)

    def test_allows_common_code_and_doc_files(self) -> None:
        allowed_samples = [
            "src/main.py",
            "web/app.js",
            "web/types.ts",
            "README.md",
            "docs/architecture.md",
        ]
        for sample in allowed_samples:
            with self.subTest(sample=sample):
                decision = self.file_filter.check_path(sample)
                self.assertTrue(decision.allowed)
                self.assertIsNone(decision.matched_pattern)
                self.assertTrue(self.file_filter.is_allowed(sample))

    def test_nested_paths_and_case_insensitivity(self) -> None:
        nested_blocked = [
            "deploy/.env.prod",
            "infra/certs/SERVER.PEM",
            "ssh/backup/ID_RSA",
            "config/prod/SECRETS.yaml",
            "cloud/AWS_Credentials_Dev.txt",
        ]
        for sample in nested_blocked:
            with self.subTest(sample=sample):
                decision = self.file_filter.check_path(sample)
                self.assertFalse(decision.allowed)
                self.assertIsNotNone(decision.matched_pattern)

    def test_blocks_binary_content_with_null_byte_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_file = Path(tmpdir) / "disguised.py"
            bin_file.write_bytes(b"print('hi')\x00\x01\x02")

            text_file = Path(tmpdir) / "clean.py"
            text_file.write_text("print('hello world')\n", encoding="utf-8")

            bin_decision = self.file_filter.check_path(bin_file)
            self.assertFalse(bin_decision.allowed)
            self.assertIsNone(bin_decision.matched_pattern)
            self.assertIn("binary", bin_decision.reason.lower())

            text_decision = self.file_filter.check_path(text_file)
            self.assertTrue(text_decision.allowed)

            no_probe_filter = FileFilter(check_binary_content=False)
            self.assertTrue(no_probe_filter.is_allowed(bin_file))

    def test_custom_and_extra_patterns(self) -> None:
        # Extend default patterns
        extended_filter = FileFilter(extra_patterns=("*.secret", "private/*"))
        self.assertFalse(extended_filter.is_allowed(".env"))
        self.assertFalse(extended_filter.is_allowed("token.secret"))
        self.assertFalse(extended_filter.is_allowed("private/notes.md"))
        self.assertTrue(extended_filter.is_allowed("public/notes.md"))

        # Replace default patterns completely
        custom_filter = FileFilter(blocked_patterns=("*.custom",))
        self.assertEqual(custom_filter.blocked_patterns, ("*.custom",))
        self.assertFalse(custom_filter.is_allowed("data.custom"))
        self.assertTrue(custom_filter.is_allowed(".env"))
        self.assertGreater(len(DEFAULT_BLOCKED_PATTERNS), 0)

    def test_filter_paths_partitions_allowed_and_blocked(self) -> None:
        paths = [
            "src/app.py",
            "deploy/.env.prod",
            "web/index.ts",
            "keys/api.key",
            "README.md",
        ]
        allowed, blocked = self.file_filter.filter_paths(paths)
        self.assertEqual(
            allowed,
            [Path("src/app.py"), Path("web/index.ts"), Path("README.md")],
        )
        self.assertEqual(len(blocked), 2)
        self.assertTrue(all(not decision.allowed for decision in blocked))
        self.assertEqual(
            [decision.matched_pattern for decision in blocked],
            [".env.*", "*.key"],
        )


if __name__ == "__main__":
    unittest.main()
