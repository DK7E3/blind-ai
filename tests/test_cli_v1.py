"""Tests for Blind AI v1.0 config (proprietary_terms) and unified CLI commands."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from blind_ai.cli.main import main
from blind_ai.core.config import BlindAIConfig


def _run_cli(argv: list[str], stdin_text: str | None = None) -> tuple[int, str, str]:
    """Invoke ``main(argv)`` capturing stdout, stderr, and optional stdin."""
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    original_stdin = sys.stdin
    try:
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
    finally:
        sys.stdin = original_stdin
    return code, out_buf.getvalue(), err_buf.getvalue()


class TestProprietaryTermsConfig(unittest.TestCase):
    """Validate ``proprietary_terms`` support in BlindAIConfig / .blindai.toml."""

    def test_proprietary_terms_root_and_rules_section_deduplicated(self) -> None:
        toml_text = (
            'proprietary_terms = ["ProjectOrion", "HyperLedgerX", "ProjectOrion"]\n'
            "\n"
            "[rules]\n"
            'proprietary_terms = ["HyperLedgerX", "InternalCodename"]\n'
            'extra_blocked_files = ["*.secret"]\n'
            'corp_ticket = "CORP-[0-9]{5}"\n'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".blindai.toml"
            cfg_path.write_text(toml_text, encoding="utf-8")
            cfg = BlindAIConfig.from_toml(cfg_path)

        self.assertEqual(
            cfg.proprietary_terms,
            ("ProjectOrion", "HyperLedgerX", "InternalCodename"),
        )
        self.assertEqual(cfg.extra_blocked_files, ("*.secret",))
        self.assertEqual(cfg.custom_rules, (("corp_ticket", "CORP-[0-9]{5}"),))

    def test_proprietary_terms_invalid_type_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / ".blindai.toml"
            cfg_path.write_text('proprietary_terms = "NotAList"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                BlindAIConfig.from_toml(cfg_path)


class TestPackAndEncryptedRestoreCLI(unittest.TestCase):
    """End-to-end tests for ``pack``, ``sanitize``, and ``restore`` with encrypted/open vaults."""

    def _create_sample_repo(self, root: Path) -> Path:
        cfg_path = root / ".blindai.toml"
        cfg_path.write_text(
            'extra_blocked_files = ["*.secret"]\n'
            'proprietary_terms = ["ProjectOrion", "ACME_CORE"]\n',
            encoding="utf-8",
        )
        (root / ".env").write_text("AWS_SECRET=topsecret\n", encoding="utf-8")
        (root / "notes.secret").write_text("confidential\n", encoding="utf-8")

        src = root / "src"
        src.mkdir()
        (src / "service.py").write_text(
            'PROJECT = "ProjectOrion"\n'
            'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n'
            'DB_IP = "10.24.108.42"\n',
            encoding="utf-8",
        )
        (src / "worker.py").write_text(
            'OWNER = "ProjectOrion"\n'
            'ENGINE = "ACME_CORE"\n'
            'SAME_KEY = "AKIAFAKE0000EXAMPLE1"\n',
            encoding="utf-8",
        )
        return cfg_path

    def test_pack_open_json_vault_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = base / "repo"
            repo.mkdir()
            cfg_path = self._create_sample_repo(repo)

            bundle_path = base / "out" / "context.md"
            vault_path = base / "out" / "vault.json"
            restored_path = base / "out" / "restored.md"

            code, out, err = _run_cli(
                [
                    "pack",
                    str(repo),
                    "--output",
                    str(bundle_path),
                    "--vault",
                    str(vault_path),
                    "--config",
                    str(cfg_path),
                    "--json",
                ]
            )
            self.assertEqual(code, 0, msg=err)
            self.assertEqual(err, "")

            summary = json.loads(out)
            self.assertFalse(summary["encrypted"])
            self.assertEqual(summary["included_count"], 3)  # .blindai.toml + 2 py files
            self.assertIn(".env", summary["blocked_files"])
            self.assertIn("notes.secret", summary["blocked_files"])
            self.assertGreaterEqual(summary["placeholders_count"], 4)

            bundle_text = bundle_path.read_text(encoding="utf-8")
            self.assertNotIn("AKIAFAKE0000EXAMPLE1", bundle_text)
            self.assertNotIn("10.24.108.42", bundle_text)
            self.assertNotIn("ProjectOrion", bundle_text)
            self.assertNotIn("ACME_CORE", bundle_text)
            self.assertIn("__BLIND_PROPRIETARY_TERM_", bundle_text)

            vault_data = json.loads(vault_path.read_text(encoding="utf-8"))
            self.assertIn("placeholder_to_value", vault_data)

            res_code, _, res_err = _run_cli(
                [
                    "restore",
                    str(bundle_path),
                    "--vault",
                    str(vault_path),
                    "--output",
                    str(restored_path),
                ]
            )
            self.assertEqual(res_code, 0, msg=res_err)
            restored_text = restored_path.read_text(encoding="utf-8")
            self.assertIn("AKIAFAKE0000EXAMPLE1", restored_text)
            self.assertIn("ProjectOrion", restored_text)
            self.assertIn("ACME_CORE", restored_text)

    def test_pack_encrypted_vault_and_restore_with_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            repo = base / "repo"
            repo.mkdir()
            cfg_path = self._create_sample_repo(repo)

            bundle_path = base / "bundle.md"
            vault_path = base / "vault.bvlt"
            passphrase = "correct-horse-battery-staple"

            code, out, err = _run_cli(
                [
                    "pack",
                    str(repo),
                    "--output",
                    str(bundle_path),
                    "--vault",
                    str(vault_path),
                    "--passphrase",
                    passphrase,
                    "--config",
                    str(cfg_path),
                    "--json",
                ]
            )
            self.assertEqual(code, 0, msg=err)
            summary = json.loads(out)
            self.assertTrue(summary["encrypted"])

            raw_vault = vault_path.read_bytes()
            self.assertTrue(raw_vault.startswith(b"BLINDVLT\x01"))
            self.assertNotIn(b"AKIAFAKE0000EXAMPLE1", raw_vault)
            self.assertNotIn(b"ProjectOrion", raw_vault)

            # Wrong passphrase must fail
            bad_code, _, bad_err = _run_cli(
                [
                    "restore",
                    str(bundle_path),
                    "--vault",
                    str(vault_path),
                    "--passphrase",
                    "wrong-passphrase",
                ]
            )
            self.assertNotEqual(bad_code, 0)
            self.assertIn("error", bad_err.lower())

            # Correct passphrase restores all placeholders
            ok_code, restored_out, ok_err = _run_cli(
                [
                    "restore",
                    str(bundle_path),
                    "--vault",
                    str(vault_path),
                    "--passphrase",
                    passphrase,
                ]
            )
            self.assertEqual(ok_code, 0, msg=ok_err)
            self.assertIn("AKIAFAKE0000EXAMPLE1", restored_out)
            self.assertIn("10.24.108.42", restored_out)
            self.assertIn("ProjectOrion", restored_out)
            self.assertIn("ACME_CORE", restored_out)

    def test_sanitize_and_restore_encrypted_passphrase_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "encrypted.bvlt"
            sample = 'TOKEN = "AKIAFAKE0000EXAMPLE1"\n'
            passphrase = "vault-secret-passphrase"

            san_code, san_out, san_err = _run_cli(
                ["sanitize", "-", "--vault", str(vault_path), "--passphrase", passphrase],
                stdin_text=sample,
            )
            self.assertEqual(san_code, 0, msg=san_err)
            self.assertNotIn("AKIAFAKE0000EXAMPLE1", san_out)
            self.assertTrue(vault_path.read_bytes().startswith(b"BLINDVLT\x01"))

            res_code, res_out, res_err = _run_cli(
                ["restore", "-", "--vault", str(vault_path), "--passphrase", passphrase],
                stdin_text=san_out,
            )
            self.assertEqual(res_code, 0, msg=res_err)
            self.assertEqual(res_out, sample)

    def test_pack_without_output_or_vault_works_for_json_and_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            self._create_sample_repo(repo)

            code_json, out_json, err_json = _run_cli(["pack", str(repo), "--json"])
            self.assertEqual(code_json, 0, msg=err_json)
            summary = json.loads(out_json)
            self.assertIsNone(summary["output"])
            self.assertIsNone(summary["vault"])
            self.assertFalse(summary["encrypted"])
            self.assertEqual(summary["included_count"], 3)

            code_md, out_md, err_md = _run_cli(["pack", str(repo)])
            self.assertEqual(code_md, 0, msg=err_md)
            self.assertIn("# Repository Context Bundle", out_md)
            self.assertNotIn("AKIAFAKE0000EXAMPLE1", out_md)


class TestProxyAndStagedScanCLI(unittest.TestCase):
    """Tests for ``proxy`` delegation and ``scan --staged`` / ``scan --config``."""

    def test_proxy_subcommand_delegates_arguments_to_server_main(self) -> None:
        with mock.patch("blind_ai.proxy.server.main", return_value=0) as mocked_main:
            code, _, err = _run_cli(
                [
                    "proxy",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "9876",
                    "--quiet",
                    "--session-ttl",
                    "120",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        mocked_main.assert_called_once_with(
            ["--host", "127.0.0.1", "--port", "9876", "--quiet", "--session-ttl", "120"]
        )

    def test_proxy_subcommand_strips_leading_double_dash(self) -> None:
        with mock.patch("blind_ai.proxy.server.main", return_value=7) as mocked_main:
            code, _, _ = _run_cli(["proxy", "--", "--port", "8765"])
        self.assertEqual(code, 7)
        mocked_main.assert_called_once_with(["--port", "8765"])

    def test_scan_config_applies_allowlist_custom_rules_and_blocked_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg_path = root / ".blindai.toml"
            cfg_path.write_text(
                'allowlist_values = ["AKIAIOSFODNN7EXAMPLE"]\n'
                'extra_blocked_files = ["*.secret"]\n'
                "\n"
                "[rules]\n"
                'corp_ticket = "CORP-[0-9]{6}"\n',
                encoding="utf-8",
            )
            code_file = root / "app.py"
            code_file.write_text(
                'DEMO = "AKIAIOSFODNN7EXAMPLE"\n'
                'TICKET = "CORP-123456"\n',
                encoding="utf-8",
            )
            secret_file = root / "dump.secret"
            secret_file.write_text("data\n", encoding="utf-8")

            code, out, err = _run_cli(
                [
                    "scan",
                    str(code_file),
                    str(secret_file),
                    "--config",
                    str(cfg_path),
                    "--format",
                    "json",
                    "--strict",
                ]
            )
            self.assertEqual(code, 1)
            self.assertEqual(err, "")
            payload = json.loads(out)
            values = {item["value"] for item in payload["findings"]}
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", values)
            self.assertIn("CORP-123456", values)
            self.assertEqual(payload["total_blocked"], 1)
            self.assertEqual(payload["blocked_files"][0]["matched_pattern"], "*.secret")

    def test_scan_staged_strict_in_real_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            init_res = subprocess.run(
                ["git", "init"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                check=False,
            )
            if init_res.returncode != 0:
                self.skipTest("git is not available in this environment")

            clean_file = repo / "clean.py"
            clean_file.write_text("VALUE = 123\n", encoding="utf-8")
            subprocess.run(["git", "add", "clean.py"], cwd=str(repo), check=True)

            prev_cwd = Path.cwd()
            try:
                os.chdir(repo)
                clean_code, clean_out, clean_err = _run_cli(
                    ["scan", "--staged", "--format", "json", "--strict"]
                )
                self.assertEqual(clean_code, 0, msg=clean_err)
                self.assertEqual(json.loads(clean_out)["total_findings"], 0)

                secret_file = repo / "leak.py"
                secret_file.write_text(
                    'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n', encoding="utf-8"
                )
                subprocess.run(["git", "add", "leak.py"], cwd=str(repo), check=True)

                leak_code, leak_out, leak_err = _run_cli(
                    ["scan", "--staged", "--format", "json", "--strict"]
                )
                self.assertEqual(leak_code, 1)
                self.assertEqual(leak_err, "")
                payload = json.loads(leak_out)
                self.assertEqual(payload["total_findings"], 1)
                self.assertEqual(payload["findings"][0]["kind"], "aws_access_key")
            finally:
                os.chdir(prev_cwd)

    def test_scan_staged_git_error_returns_exit_code_2(self) -> None:
        failed_proc = subprocess.CompletedProcess(
            args=["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            returncode=128,
            stdout="",
            stderr="fatal: not a git repository",
        )
        with mock.patch("blind_ai.cli.main.subprocess.run", return_value=failed_proc):
            code, _, err = _run_cli(["scan", "--staged", "--strict"])
        self.assertEqual(code, 2)
        self.assertIn("not a git repository", err)

    def test_scan_staged_reads_git_index_not_unstaged_working_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            init_res = subprocess.run(
                ["git", "init"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                check=False,
            )
            if init_res.returncode != 0:
                self.skipTest("git is not available in this environment")

            tracked = repo / "config.py"
            tracked.write_text("SAFE_VALUE = 123\n", encoding="utf-8")
            subprocess.run(["git", "add", "config.py"], cwd=str(repo), check=True)

            # Working tree has an unstaged secret, while staged git index is clean.
            tracked.write_text(
                'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n', encoding="utf-8"
            )

            prev_cwd = Path.cwd()
            try:
                os.chdir(repo)
                code, out, err = _run_cli(
                    ["scan", "--staged", "--format", "json", "--strict"]
                )
                self.assertEqual(code, 0, msg=err)
                payload = json.loads(out)
                self.assertEqual(payload["total_findings"], 0)

                # Now stage the secret and overwrite disk with clean content;
                # scan --staged must still catch the secret in the git index.
                subprocess.run(["git", "add", "config.py"], cwd=str(repo), check=True)
                tracked.write_text("SAFE_VALUE = 456\n", encoding="utf-8")

                code2, out2, err2 = _run_cli(
                    ["scan", "--staged", "--format", "json", "--strict"]
                )
                self.assertEqual(code2, 1, msg=err2)
                payload2 = json.loads(out2)
                self.assertEqual(payload2["total_findings"], 1)
                self.assertEqual(payload2["findings"][0]["kind"], "aws_access_key")
            finally:
                os.chdir(prev_cwd)


class TestApplyEnvPassphraseAndHybridCLI(unittest.TestCase):
    """Tests for ``blind-ai apply``, ``BLIND_AI_PASSPHRASE``, and ``HybridScanner`` in CLI."""

    def test_apply_restores_markdown_blocks_and_blocks_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            vault_path = base / "session.vault.enc"
            target_dir = base / "restored_repo"
            passphrase = "env-vault-secret-2026"

            sample = (
                'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n'
                "# temporary staging password: WinterFictionalPass!2026\n"
            )
            with mock.patch.dict(
                os.environ, {"BLIND_AI_PASSPHRASE": passphrase}, clear=False
            ):
                san_code, san_out, san_err = _run_cli(
                    ["sanitize", "-", "--vault", str(vault_path)],
                    stdin_text=sample,
                )
            self.assertEqual(san_code, 0, msg=san_err)
            self.assertTrue(vault_path.read_bytes().startswith(b"BLINDVLT\x01"))
            self.assertNotIn("AKIAFAKE0000EXAMPLE1", san_out)
            self.assertNotIn("WinterFictionalPass!2026", san_out)

            ai_markdown = (
                "Here are the updated files:\n\n"
                "### `src/settings.py`\n\n"
                "```python\n"
                f"{san_out.rstrip()}\n"
                "```\n\n"
                "### `README.md`\n"
                "````markdown\n"
                "Updated configuration for staging.\n"
                "````\n"
            )
            md_path = base / "ai_reply.md"
            md_path.write_text(ai_markdown, encoding="utf-8")

            with mock.patch.dict(
                os.environ, {"BLIND_AI_PASSPHRASE": passphrase}, clear=False
            ):
                app_code, app_out, app_err = _run_cli(
                    [
                        "apply",
                        str(md_path),
                        "--vault",
                        str(vault_path),
                        "--target-dir",
                        str(target_dir),
                        "--json",
                    ]
                )
            self.assertEqual(app_code, 0, msg=app_err)
            summary = json.loads(app_out)
            self.assertEqual(summary["applied_count"], 2)
            self.assertEqual(
                summary["applied_files"], ["src/settings.py", "README.md"]
            )

            restored_py = (target_dir / "src" / "settings.py").read_text(
                encoding="utf-8"
            )
            self.assertIn("AKIAFAKE0000EXAMPLE1", restored_py)
            self.assertIn("WinterFictionalPass!2026", restored_py)

            # Path traversal via '..' must be rejected with non-zero exit code.
            traversal_md = (
                "### `../escaped.py`\n"
                "```python\n"
                "x = 1\n"
                "```\n"
            )
            with mock.patch.dict(
                os.environ, {"BLIND_AI_PASSPHRASE": passphrase}, clear=False
            ):
                bad_code, _, bad_err = _run_cli(
                    [
                        "apply",
                        "-",
                        "--vault",
                        str(vault_path),
                        "--target-dir",
                        str(target_dir),
                    ],
                    stdin_text=traversal_md,
                )
            self.assertNotEqual(bad_code, 0)
            self.assertIn("traversal", bad_err.lower())
            self.assertFalse((base / "escaped.py").exists())

            # Absolute path must also be rejected.
            abs_md = (
                "### `/etc/passwd`\n"
                "```text\n"
                "root\n"
                "```\n"
            )
            with mock.patch.dict(
                os.environ, {"BLIND_AI_PASSPHRASE": passphrase}, clear=False
            ):
                abs_code, _, abs_err = _run_cli(
                    [
                        "apply",
                        "-",
                        "--vault",
                        str(vault_path),
                        "--target-dir",
                        str(target_dir),
                    ],
                    stdin_text=abs_md,
                )
            self.assertNotEqual(abs_code, 0)
            self.assertIn("absolute", abs_err.lower())

    def test_scan_and_pack_use_hybrid_scanner_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            (repo / ".blindai.toml").write_text(
                'allowlist_values = ["AKIAIOSFODNN7EXAMPLE"]\n'
                "[rules]\n"
                'internal_ticket = "OPS-[0-9]{4}"\n',
                encoding="utf-8",
            )
            (repo / "notes.py").write_text(
                'ALLOWED_DEMO = "AKIAIOSFODNN7EXAMPLE"\n'
                'TICKET = "OPS-4242"\n'
                "# emergency database password: WinterFictionalPass!2026\n",
                encoding="utf-8",
            )

            scan_code, scan_out, scan_err = _run_cli(
                ["scan", str(repo), "--format", "json", "--strict"]
            )
            self.assertEqual(scan_code, 1, msg=scan_err)
            scan_payload = json.loads(scan_out)
            kinds = {item["kind"] for item in scan_payload["findings"]}
            values = {item["value"] for item in scan_payload["findings"]}
            self.assertIn("sensitive_comment", kinds)
            self.assertIn("internal_ticket", kinds)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", values)

            vault_path = Path(tmpdir) / "vault.bvlt"
            bundle_path = Path(tmpdir) / "bundle.md"
            with mock.patch.dict(
                os.environ, {"BLIND_AI_PASSPHRASE": "env-pack-pass"}, clear=False
            ):
                pack_code, pack_out, pack_err = _run_cli(
                    [
                        "pack",
                        str(repo),
                        "-o",
                        str(bundle_path),
                        "--vault",
                        str(vault_path),
                        "--json",
                    ]
                )
            self.assertEqual(pack_code, 0, msg=pack_err)
            pack_summary = json.loads(pack_out)
            self.assertTrue(pack_summary["encrypted"])
            bundle_text = bundle_path.read_text(encoding="utf-8")
            self.assertNotIn("WinterFictionalPass!2026", bundle_text)
            self.assertNotIn("OPS-4242", bundle_text)
            self.assertIn("AKIAIOSFODNN7EXAMPLE", bundle_text)

    def test_apply_blocks_protected_dirs_blindai_toml_and_filtered_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            vault_path = base / "vault.json"
            target_dir = base / "repo"
            target_dir.mkdir()

            san_code, _, san_err = _run_cli(
                ["sanitize", "-", "--vault", str(vault_path)],
                stdin_text="x = 1\n",
            )
            self.assertEqual(san_code, 0, msg=san_err)

            forbidden_paths = [
                ".git/hooks/pre-commit",
                ".git/config",
                ".agents/hooks.json",
                ".github/workflows/pwn.yml",
                ".venv/lib/site.py",
                "__pycache__/evil.py",
                "node_modules/pkg/index.js",
                ".blindai.toml",
                ".env",
                ".env.production",
                "certs/private.pem",
                "keys/server.key",
            ]
            for forbidden in forbidden_paths:
                malicious_md = (
                    f"### `{forbidden}`\n"
                    "```text\n"
                    "pwned\n"
                    "```\n"
                )
                code, _, err = _run_cli(
                    [
                        "apply",
                        "-",
                        "--vault",
                        str(vault_path),
                        "--target-dir",
                        str(target_dir),
                    ],
                    stdin_text=malicious_md,
                )
                self.assertNotEqual(
                    code,
                    0,
                    msg=f"Expected non-zero exit code for forbidden path {forbidden!r}",
                )
                self.assertIn("error", err.lower())
                self.assertFalse((target_dir / forbidden).exists())

    def test_pack_cli_accepts_max_tokens_max_file_bytes_and_case_insensitive_terms(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            (repo / ".blindai.toml").write_text(
                'proprietary_terms = ["ProjectOrion"]\n',
                encoding="utf-8",
            )
            (repo / "a_small.py").write_text(
                'NAME = "projectorion"\nUPPER = "PROJECTORION"\n',
                encoding="utf-8",
            )
            (repo / "b_oversized.py").write_text(
                "DATA = '" + ("X" * 400) + "'\n",
                encoding="utf-8",
            )
            (repo / "c_budget.py").write_text(
                "MORE = '" + ("Y" * 180) + "'\n",
                encoding="utf-8",
            )

            bundle_path = Path(tmpdir) / "bundle.md"
            code, out, err = _run_cli(
                [
                    "pack",
                    str(repo),
                    "--output",
                    str(bundle_path),
                    "--max-file-bytes",
                    "250",
                    "--max-tokens",
                    "95",
                    "--case-insensitive-terms",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, msg=err)
            summary = json.loads(out)
            self.assertIn("a_small.py", summary["included_files"])
            self.assertIn("b_oversized.py", summary["blocked_files"])
            self.assertIn("c_budget.py", summary["blocked_files"])

            bundle_text = bundle_path.read_text(encoding="utf-8")
            self.assertNotIn("projectorion", bundle_text.lower())
            self.assertIn("__BLIND_PROPRIETARY_TERM_", bundle_text)


if __name__ == "__main__":
    unittest.main()
