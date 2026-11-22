"""Unit tests for pyproject.toml metadata and BlindAIConfig (.blindai.toml)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
import tempfile
import tomllib
import unittest

from blind_ai.core.config import BlindAIConfig
from blind_ai.core.scanner import DeterministicScanner, Finding

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestPyprojectToml(unittest.TestCase):
    """Validate installable package metadata in pyproject.toml."""

    def test_pyproject_is_valid_toml_with_blind_ai_script(self) -> None:
        pyproject_path = PROJECT_ROOT / "pyproject.toml"
        self.assertTrue(pyproject_path.is_file(), "pyproject.toml must exist")

        with pyproject_path.open("rb") as fh:
            data = tomllib.load(fh)

        build_system = data.get("build-system", {})
        self.assertEqual(build_system.get("build-backend"), "setuptools.build_meta")
        self.assertTrue(
            any("setuptools" in req for req in build_system.get("requires", []))
        )

        project = data.get("project", {})
        self.assertEqual(project.get("name"), "blind-ai")
        self.assertEqual(project.get("requires-python"), ">=3.12")
        self.assertEqual(project.get("dependencies"), [])

        scripts = project.get("scripts", {})
        self.assertEqual(scripts.get("blind-ai"), "blind_ai.cli.main:main")

        packages_find = (
            data.get("tool", {})
            .get("setuptools", {})
            .get("packages", {})
            .get("find", {})
        )
        self.assertEqual(packages_find.get("where"), ["src"])


class TestBlindAIConfig(unittest.TestCase):
    """Validate .blindai.toml loading, allowlist filtering, and FileFilter wiring."""

    def test_from_toml_missing_file_returns_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / ".blindai.toml"
            cfg = BlindAIConfig.from_toml(missing)

        self.assertEqual(cfg.allowlist_values, ())
        self.assertEqual(cfg.allowlist_patterns, ())
        self.assertEqual(cfg.extra_blocked_files, ())
        self.assertEqual(cfg.custom_rules, ())

    def test_from_toml_root_keys(self) -> None:
        toml_text = (
            'allowlist_values = ["AKIAIOSFODNN7EXAMPLE", "192.168.0.1"]\n'
            'allowlist_patterns = ["^TEST_TOKEN_[0-9]+$", "example\\\\.internal"]\n'
            'extra_blocked_files = ["*.secret", "private/*"]\n'
            'custom_rules = { corp_id = "CORP-[0-9]{6}" }\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / ".blindai.toml"
            cfg_path.write_text(toml_text, encoding="utf-8")
            cfg = BlindAIConfig.from_toml(cfg_path)

        self.assertEqual(
            cfg.allowlist_values, ("AKIAIOSFODNN7EXAMPLE", "192.168.0.1")
        )
        self.assertEqual(
            cfg.allowlist_patterns, ("^TEST_TOKEN_[0-9]+$", r"example\.internal")
        )
        self.assertEqual(cfg.extra_blocked_files, ("*.secret", "private/*"))
        self.assertEqual(cfg.custom_rules, (("corp_id", "CORP-[0-9]{6}"),))
        self.assertEqual(len(cfg.compiled_custom_rules), 1)
        self.assertIsNotNone(cfg.compiled_custom_rules[0][1].search("id=CORP-123456"))

    def test_from_toml_sections_allowlist_and_rules(self) -> None:
        toml_text = (
            "[allowlist]\n"
            'values = ["10.0.0.1"]\n'
            'patterns = ["^DUMMY_.*"]\n'
            "\n"
            "[rules]\n"
            'extra_blocked_files = ["*.vault", "secrets_dir/*"]\n'
            'internal_ticket = "TKT-[0-9]{4}"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / ".blindai.toml"
            cfg_path.write_text(toml_text, encoding="utf-8")
            cfg = BlindAIConfig.from_toml(cfg_path)

        self.assertEqual(cfg.allowlist_values, ("10.0.0.1",))
        self.assertEqual(cfg.allowlist_patterns, ("^DUMMY_.*",))
        self.assertEqual(cfg.extra_blocked_files, ("*.vault", "secrets_dir/*"))
        self.assertEqual(cfg.custom_rules, (("internal_ticket", "TKT-[0-9]{4}"),))

    def test_invalid_regex_in_toml_raises_value_error(self) -> None:
        bad_allowlist = 'allowlist_patterns = ["[unclosed"]\n'
        bad_custom = '[rules]\nbroken_rule = "(unclosed"\n'

        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "bad1.toml"
            path1.write_text(bad_allowlist, encoding="utf-8")
            with self.assertRaises(ValueError):
                BlindAIConfig.from_toml(path1)

            path2 = Path(tmp) / "bad2.toml"
            path2.write_text(bad_custom, encoding="utf-8")
            with self.assertRaises(ValueError):
                BlindAIConfig.from_toml(path2)

    def test_discover_finds_parent_config_and_falls_back_to_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "pkg" / "sub"
            nested.mkdir(parents=True)

            # Without .blindai.toml in hierarchy (using unique filename to isolate
            # from any config higher on the host filesystem)
            empty_cfg = BlindAIConfig.discover(
                nested, filename=".nonexistent-blindai-test.toml"
            )
            self.assertEqual(empty_cfg, BlindAIConfig())

            cfg_file = root / ".blindai.toml"
            cfg_file.write_text(
                'allowlist_values = ["127.0.0.1"]\nextra_blocked_files = ["*.bak"]\n',
                encoding="utf-8",
            )
            discovered = BlindAIConfig.discover(nested)
            self.assertEqual(discovered.allowlist_values, ("127.0.0.1",))
            self.assertEqual(discovered.extra_blocked_files, ("*.bak",))

    def test_is_allowlisted_and_filter_findings_preserve_non_allowlisted(self) -> None:
        cfg = BlindAIConfig(
            allowlist_values=("AKIAIOSFODNN7EXAMPLE",),
            allowlist_patterns=(r"^10\.0\.0\.",),
        )

        self.assertTrue(cfg.is_allowlisted("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(cfg.is_allowlisted("10.0.0.42"))
        self.assertFalse(cfg.is_allowlisted("AKIA1234567890ABCDEF"))
        self.assertFalse(cfg.is_allowlisted("192.168.1.10"))

        f_fp_exact = Finding(
            kind="aws_access_key",
            value="AKIAIOSFODNN7EXAMPLE",
            start=0,
            end=20,
            line=1,
            source="regex",
            confidence=0.98,
        )
        f_real_key = Finding(
            kind="aws_access_key",
            value="AKIA1234567890ABCDEF",
            start=25,
            end=45,
            line=2,
            source="regex",
            confidence=0.98,
        )
        f_fp_regex = Finding(
            kind="private_ip",
            value="10.0.0.42",
            start=50,
            end=59,
            line=3,
            source="regex",
            confidence=0.90,
        )
        f_real_ip = Finding(
            kind="private_ip",
            value="192.168.1.10",
            start=65,
            end=77,
            line=4,
            source="regex",
            confidence=0.90,
        )

        filtered = cfg.filter_findings([f_fp_exact, f_real_key, f_fp_regex, f_real_ip])
        self.assertEqual(filtered, [f_real_key, f_real_ip])

    def test_filter_findings_with_real_scanner(self) -> None:
        sample = (
            'DEMO_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'PROD_KEY = "AKIA9999888877776666"\n'
            'LOCAL_IP = "10.0.0.5"\n'
            'PROD_IP = "172.16.10.20"\n'
        )
        scanner = DeterministicScanner()
        raw_findings = scanner.scan_text(sample)
        self.assertGreaterEqual(len(raw_findings), 4)

        cfg = BlindAIConfig(
            allowlist_values=("AKIAIOSFODNN7EXAMPLE",),
            allowlist_patterns=(r"^10\.0\.0\.\d+$",),
        )
        remaining = cfg.filter_findings(raw_findings)
        remaining_values = {f.value for f in remaining}

        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", remaining_values)
        self.assertNotIn("10.0.0.5", remaining_values)
        self.assertIn("AKIA9999888877776666", remaining_values)
        self.assertIn("172.16.10.20", remaining_values)

    def test_build_file_filter_blocks_extra_patterns(self) -> None:
        cfg = BlindAIConfig(extra_blocked_files=("*.secret", "private/*"))
        file_filter = cfg.build_file_filter(check_binary_content=False)

        secret_decision = file_filter.check_path("config/app.secret")
        self.assertFalse(secret_decision.allowed)
        self.assertEqual(secret_decision.matched_pattern, "*.secret")

        private_decision = file_filter.check_path("private/notes.txt")
        self.assertFalse(private_decision.allowed)
        self.assertEqual(private_decision.matched_pattern, "private/*")

        # Default blocked patterns remain active
        self.assertFalse(file_filter.is_allowed(".env"))
        # Regular files remain allowed
        self.assertTrue(file_filter.is_allowed("src/blind_ai/core/config.py"))

    def test_config_is_frozen(self) -> None:
        cfg = BlindAIConfig()
        with self.assertRaises(FrozenInstanceError):
            cfg.allowlist_values = ("x",)  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
