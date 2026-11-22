"""Unit and CLI end-to-end tests for ``blind_ai.cli.main`` and ``python -m blind_ai``."""

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

from blind_ai.cli.main import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"


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


class TestScanCommand(unittest.TestCase):
    """Tests for the ``scan`` subcommand."""

    def test_scan_detects_secret_text_and_json_and_strict_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = Path(tmpdir) / "app_config.py"
            secret_file.write_text(
                'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n'
                'HOST_IP = "10.24.108.42"\n',
                encoding="utf-8",
            )

            # Text output without --strict returns 0
            code, out, err = _run_cli(["scan", str(secret_file), "--format", "text"])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertIn("aws_access_key", out)
            self.assertIn("private_ip", out)

            # JSON output with --strict returns non-zero (1)
            code_strict, out_json, err_strict = _run_cli(
                ["scan", str(secret_file), "--format", "json", "--strict"]
            )
            self.assertEqual(code_strict, 1)
            self.assertEqual(err_strict, "")

            payload = json.loads(out_json)
            self.assertTrue(payload["strict"])
            self.assertGreaterEqual(payload["total_findings"], 2)
            kinds = {item["kind"] for item in payload["findings"]}
            self.assertIn("aws_access_key", kinds)
            self.assertIn("private_ip", kinds)
            self.assertEqual(payload["total_blocked"], 0)

    def test_scan_clean_file_strict_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_file = Path(tmpdir) / "math_utils.py"
            clean_file.write_text(
                "def add(a: int, b: int) -> int:\n"
                "    return a + b\n",
                encoding="utf-8",
            )

            code, out, err = _run_cli(
                ["scan", str(clean_file), "--format", "json", "--strict"]
            )
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            payload = json.loads(out)
            self.assertEqual(payload["total_findings"], 0)
            self.assertEqual(payload["total_blocked"], 0)

    def test_scan_directory_flags_blocked_file_in_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / ".env").write_text("SECRET=placeholder\n", encoding="utf-8")
            (root / "clean.py").write_text("VALUE = 42\n", encoding="utf-8")

            code, out, err = _run_cli(["scan", str(root), "--format", "json", "--strict"])
            self.assertEqual(code, 1)
            self.assertEqual(err, "")
            payload = json.loads(out)
            self.assertEqual(payload["total_blocked"], 1)
            self.assertEqual(payload["blocked_files"][0]["matched_pattern"], ".env")

    def test_scan_stdin(self) -> None:
        sample = 'TOKEN = "ghp_FakeExampleToken00001111222233334444"\n'
        code, out, err = _run_cli(
            ["scan", "-", "--format", "json", "--strict"],
            stdin_text=sample,
        )
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertEqual(payload["total_findings"], 1)
        self.assertEqual(payload["findings"][0]["path"], "<stdin>")
        self.assertEqual(payload["findings"][0]["kind"], "github_token")


class TestSanitizeRestoreCommand(unittest.TestCase):
    """End-to-end tests for ``sanitize`` and ``restore`` with a local vault file."""

    def test_sanitize_and_restore_roundtrip_with_local_vault(self) -> None:
        original_text = (
            'AWS_KEY = "AKIAFAKE0000EXAMPLE1"\n'
            'OPENAI_KEY = "sk-proj-fake0000example1111token2222abcd3333efgh4444"\n'
            'DB_HOST = "192.168.10.25"\n'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            input_path = root / "input.py"
            sanitized_path = root / "sanitized.py"
            restored_path = root / "restored.py"
            vault_path = root / "vault.json"

            input_path.write_text(original_text, encoding="utf-8")

            san_code, san_out, san_err = _run_cli(
                [
                    "sanitize",
                    str(input_path),
                    "--vault",
                    str(vault_path),
                    "--output",
                    str(sanitized_path),
                ]
            )
            self.assertEqual(san_code, 0)
            self.assertEqual(san_out, "")
            self.assertEqual(san_err, "")
            self.assertTrue(vault_path.exists())

            sanitized_text = sanitized_path.read_text(encoding="utf-8")
            self.assertNotIn("AKIAFAKE0000EXAMPLE1", sanitized_text)
            self.assertNotIn("sk-proj-fake0000example1111token2222abcd3333efgh4444", sanitized_text)
            self.assertNotIn("192.168.10.25", sanitized_text)
            self.assertIn("__BLIND_", sanitized_text)

            vault_data = json.loads(vault_path.read_text(encoding="utf-8"))
            self.assertIn("session_id", vault_data)
            self.assertEqual(len(vault_data["placeholder_to_value"]), 3)

            res_code, res_out, res_err = _run_cli(
                [
                    "restore",
                    str(sanitized_path),
                    "--vault",
                    str(vault_path),
                    "--output",
                    str(restored_path),
                ]
            )
            self.assertEqual(res_code, 0)
            self.assertEqual(res_out, "")
            self.assertEqual(res_err, "")
            self.assertEqual(restored_path.read_text(encoding="utf-8"), original_text)

    def test_sanitize_reuses_existing_vault_via_stdin_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "session_vault.json"
            sample = "key=AKIAFAKE0000EXAMPLE1\n"

            code1, out1, err1 = _run_cli(
                ["sanitize", "-", "--vault", str(vault_path)],
                stdin_text=sample,
            )
            self.assertEqual(code1, 0)
            self.assertEqual(err1, "")

            code2, out2, err2 = _run_cli(
                ["sanitize", "-", "--vault", str(vault_path)],
                stdin_text=sample,
            )
            self.assertEqual(code2, 0)
            self.assertEqual(err2, "")
            self.assertEqual(out1, out2)

            code3, restored, err3 = _run_cli(
                ["restore", "-", "--vault", str(vault_path)],
                stdin_text=out2,
            )
            self.assertEqual(code3, 0)
            self.assertEqual(err3, "")
            self.assertEqual(restored, sample)

    def test_restore_missing_or_invalid_vault_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_vault = Path(tmpdir) / "does_not_exist.json"
            code_missing, _, err_missing = _run_cli(
                ["restore", "-", "--vault", str(missing_vault)],
                stdin_text="__BLIND_AWS_ACCESS_KEY_001__",
            )
            self.assertNotEqual(code_missing, 0)
            self.assertIn("not found", err_missing.lower())

            invalid_vault = Path(tmpdir) / "corrupt.json"
            invalid_vault.write_text("{not valid json", encoding="utf-8")
            code_invalid, _, err_invalid = _run_cli(
                ["restore", "-", "--vault", str(invalid_vault)],
                stdin_text="__BLIND_AWS_ACCESS_KEY_001__",
            )
            self.assertNotEqual(code_invalid, 0)
            self.assertIn("error", err_invalid.lower())


class TestBenchmarkCommand(unittest.TestCase):
    """Tests for the ``benchmark`` subcommand (in-process and subprocess)."""

    def test_benchmark_json_output_contains_h1_metrics(self) -> None:
        code, out, err = _run_cli(["benchmark", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")

        payload = json.loads(out)
        self.assertIn("overall", payload)
        self.assertIn("h1_structured", payload)
        for section_name in ("overall", "h1_structured"):
            section = payload[section_name]
            for key in ("recall", "precision", "avg_latency_ms", "tp", "fp", "fn", "tn"):
                self.assertIn(key, section)

        self.assertGreaterEqual(payload["h1_structured"]["recall"], 0.99)

    def test_benchmark_subprocess_module_execution(self) -> None:
        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{SRC_DIR}{os.pathsep}{existing_pythonpath}"
            if existing_pythonpath
            else str(SRC_DIR)
        )

        result = subprocess.run(
            [sys.executable, "-m", "blind_ai", "benchmark"],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("recall", result.stdout)
        self.assertIn("precision", result.stdout)
        self.assertIn("avg_latency_ms", result.stdout)
        self.assertIn("H1", result.stdout)


if __name__ == "__main__":
    unittest.main()
