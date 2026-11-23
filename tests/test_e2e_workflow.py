"""End-to-end CLI workflow tests for Blind AI (pack -> 0 leaks -> restore -> execute).

Uses only the Python 3.12 standard library.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

_PLACEHOLDER_RE = re.compile(r"__BLIND_[A-Z0-9_]+__")


class TestE2EWorkflow(unittest.TestCase):
    """Validate the full CLI workflow from repository packing to executable restoration."""

    def _cli_env(self) -> dict[str, str]:
        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            f"{SRC_DIR}{os.pathsep}{existing}" if existing else str(SRC_DIR)
        )
        return env

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "blind_ai", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self._cli_env(),
            check=False,
        )

    def test_pack_zero_leaks_restore_and_execute_e2e(self) -> None:
        """Pack a mini-repo with encrypted vault, verify 0 leaks, restore AI code, and run it."""
        env_secret = "S3cr3tEnvDbPass_998877"
        api_key = "AKIAIOSFODNN7EXAMPLE"
        private_ip = "10.42.18.99"
        proprietary_term = "ProjectHelios"
        passphrase = "correct-horse-battery-staple-2026"

        with tempfile.TemporaryDirectory(prefix="blind_ai_e2e_") as tmp_dir:
            root = Path(tmp_dir)
            repo = root / "mini_repo"
            app_dir = repo / "app"
            app_dir.mkdir(parents=True)

            # 1. Blocked .env file with sensitive credentials
            (repo / ".env").write_text(
                f"DATABASE_URL=postgres://admin:{env_secret}@10.99.0.5:5432/prod\n",
                encoding="utf-8",
            )

            # 2. Project configuration with proprietary_terms
            (repo / ".blindai.toml").write_text(
                f'proprietary_terms = ["{proprietary_term}"]\n',
                encoding="utf-8",
            )

            # 3. Python source files with secret, private IP, and repeated proprietary term
            (app_dir / "config.py").write_text(
                "\n".join(
                    [
                        f'AWS_ACCESS_KEY = "{api_key}"',
                        f'INTERNAL_DB_HOST = "{private_ip}"',
                        f'PROJECT_CODENAME = "{proprietary_term}"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (app_dir / "service.py").write_text(
                "\n".join(
                    [
                        "def describe_service() -> str:",
                        f'    return "{proprietary_term} connected to {private_ip}"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            bundle_path = root / "out" / "context_bundle.md"
            vault_path = root / "out" / "session.vault.enc"

            # 4. Run `python -m blind_ai pack` with encrypted vault and JSON summary
            pack_proc = self._run_cli(
                "pack",
                str(repo),
                "-o",
                str(bundle_path),
                "--vault",
                str(vault_path),
                "--passphrase",
                passphrase,
                "--json",
            )
            self.assertEqual(
                pack_proc.returncode,
                0,
                msg=f"pack failed:\nSTDOUT:\n{pack_proc.stdout}\nSTDERR:\n{pack_proc.stderr}",
            )

            summary = json.loads(pack_proc.stdout)
            self.assertTrue(summary["encrypted"])
            self.assertGreaterEqual(summary["blocked_count"], 1)
            self.assertIn(".env", summary["blocked_files"])
            self.assertIn("app/config.py", summary["included_files"])
            self.assertIn("app/service.py", summary["included_files"])
            self.assertNotIn(".env", summary["included_files"])
            self.assertGreaterEqual(summary["placeholders_count"], 3)

            # 5. Verify 0 leaks in bundle and encrypted vault
            bundle_text = bundle_path.read_text(encoding="utf-8")
            vault_raw = vault_path.read_text(encoding="utf-8", errors="replace")

            sensitive_values = [env_secret, api_key, private_ip, proprietary_term]
            for secret in sensitive_values:
                self.assertNotIn(
                    secret,
                    bundle_text,
                    msg=f"Sensitive value leaked into bundle: {secret!r}",
                )
                self.assertNotIn(
                    secret,
                    vault_raw,
                    msg=f"Sensitive value leaked in plaintext inside encrypted vault: {secret!r}",
                )

            # 6. Extract placeholders generated in bundle and verify cross-file consistency
            aws_match = re.search(
                r'AWS_ACCESS_KEY = "(__BLIND_[A-Z0-9_]+__)"', bundle_text
            )
            ip_match = re.search(
                r'INTERNAL_DB_HOST = "(__BLIND_[A-Z0-9_]+__)"', bundle_text
            )
            term_match = re.search(
                r'PROJECT_CODENAME = "(__BLIND_[A-Z0-9_]+__)"', bundle_text
            )
            service_match = re.search(
                r'return "(__BLIND_[A-Z0-9_]+__) connected to (__BLIND_[A-Z0-9_]+__)"',
                bundle_text,
            )

            self.assertIsNotNone(aws_match, "AWS placeholder not found in bundle")
            self.assertIsNotNone(ip_match, "Private IP placeholder not found in bundle")
            self.assertIsNotNone(
                term_match, "Proprietary term placeholder not found in bundle"
            )
            self.assertIsNotNone(
                service_match, "Sanitized service.py line not found in bundle"
            )

            assert aws_match and ip_match and term_match and service_match
            aws_ph = aws_match.group(1)
            ip_ph = ip_match.group(1)
            term_ph = term_match.group(1)

            # Same proprietary term and IP must share identical placeholders across files
            self.assertEqual(service_match.group(1), term_ph)
            self.assertEqual(service_match.group(2), ip_ph)

            # 7. Simulate LLM response referencing the placeholders
            ai_response_path = root / "ai_response.py"
            ai_response_path.write_text(
                "\n".join(
                    [
                        "import json",
                        "",
                        "def build_runtime_config() -> dict[str, str]:",
                        "    return {",
                        f'        "aws_key": "{aws_ph}",',
                        f'        "db_host": "{ip_ph}",',
                        f'        "project": "{term_ph}",',
                        f'        "dsn": f"https://{ip_ph}/api/{term_ph}",',
                        "    }",
                        "",
                        'if __name__ == "__main__":',
                        "    print(json.dumps(build_runtime_config(), sort_keys=True))",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            # 8. Verify restore rejects an incorrect passphrase
            bad_restore = self._run_cli(
                "restore",
                str(ai_response_path),
                "--vault",
                str(vault_path),
                "--passphrase",
                "wrong-passphrase-must-fail",
            )
            self.assertNotEqual(bad_restore.returncode, 0)
            for secret in sensitive_values:
                self.assertNotIn(secret, bad_restore.stdout)

            # 9. Run `python -m blind_ai restore` with the correct passphrase
            restored_path = root / "restored_script.py"
            restore_proc = self._run_cli(
                "restore",
                str(ai_response_path),
                "--vault",
                str(vault_path),
                "--passphrase",
                passphrase,
                "-o",
                str(restored_path),
            )
            self.assertEqual(
                restore_proc.returncode,
                0,
                msg=f"restore failed:\nSTDOUT:\n{restore_proc.stdout}\nSTDERR:\n{restore_proc.stderr}",
            )

            restored_code = restored_path.read_text(encoding="utf-8")
            self.assertIsNone(
                _PLACEHOLDER_RE.search(restored_code),
                msg=f"Unrestored placeholder found:\n{restored_code}",
            )

            # 10. Validate syntax via ast.parse() and execute restored Python script
            parsed_ast = ast.parse(restored_code, filename=str(restored_path))
            self.assertIsInstance(parsed_ast, ast.Module)

            exec_proc = subprocess.run(
                [sys.executable, str(restored_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(
                exec_proc.returncode,
                0,
                msg=f"Restored script execution failed:\nSTDERR:\n{exec_proc.stderr}",
            )

            output_data = json.loads(exec_proc.stdout)
            self.assertEqual(
                output_data,
                {
                    "aws_key": api_key,
                    "db_host": private_ip,
                    "dsn": f"https://{private_ip}/api/{proprietary_term}",
                    "project": proprietary_term,
                },
            )


if __name__ == "__main__":
    unittest.main()
