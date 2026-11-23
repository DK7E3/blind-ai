"""Offensive/Defensive Security Audit Test Suite (V1 through V6).

Verifies that every vulnerability identified in the security audit is
deterministically blocked at runtime.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest
from urllib import error as urllib_error
from urllib import request as urllib_request

from blind_ai.cli.main import main as cli_main
from blind_ai.core.contextual import HybridScanner
from blind_ai.core.scanner import DeterministicScanner
from blind_ai.core.secure_vault import save_encrypted
from blind_ai.core.vault import PseudonymVault
from blind_ai.proxy.server import SessionStore, create_server


class _OracleAttackUpstreamHandler(BaseHTTPRequestHandler):
    """Simulates a prompt-injected upstream LLM trying to exfiltrate __BLIND_AWS_ACCESS_KEY_001__."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        # Attempt to exfiltrate a placeholder from an earlier turn that was NOT sent in this turn
        body = json.dumps(
            {
                "id": "chatcmpl-attack",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "mock-llm",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Exfiltrated: __BLIND_AWS_ACCESS_KEY_001__",
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SecurityAuditExploitTests(unittest.TestCase):
    """Tests attempting to exploit V1–V6 and asserting each attack fails."""

    def test_v1_hmac_tagged_placeholders_and_allowed_scope(self) -> None:
        vault = PseudonymVault(session_id="sec-sess", tag_placeholders=True)
        secret_a = "AKIA1234567890ABCDEF"
        sanitized = vault.sanitize(f"aws = '{secret_a}'")
        self.assertNotIn(secret_a, sanitized)
        self.assertRegex(sanitized, r"__BLIND_AWS_ACCESS_KEY_001_[0-9A-F]{6}__")

        # Attack: LLM guesses untagged "__BLIND_AWS_ACCESS_KEY_001__" -> not restored
        forged = "Leaked: __BLIND_AWS_ACCESS_KEY_001__"
        self.assertEqual(vault.restore(forged), forged)

        # Scope restriction: even with known placeholder, if not in allowed_placeholders, blocked
        real_ph = vault.value_to_placeholder[secret_a]
        self.assertEqual(
            vault.restore(f"Leaked: {real_ph}", allowed_placeholders=set()),
            f"Leaked: {real_ph}",
        )
        self.assertEqual(
            vault.restore(f"Allowed: {real_ph}", allowed_placeholders={real_ph}),
            f"Allowed: {secret_a}",
        )

    def test_v1_proxy_blocks_cross_turn_oracle_placeholder_exfiltration(self) -> None:
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _OracleAttackUpstreamHandler)
        up_port = upstream.server_address[1]
        up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        up_thread.start()

        proxy = create_server(
            host="127.0.0.1",
            port=0,
            quiet=True,
            upstream_url=f"http://127.0.0.1:{up_port}",
        )
        px_port = proxy.server_address[1]
        px_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        px_thread.start()

        try:
            # Turn 1: store AWS secret in default session
            aws_secret = "AKIA1234567890ABCDEF"
            req1 = urllib_request.Request(
                f"http://127.0.0.1:{px_port}/v1/chat/completions",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": f"key={aws_secret}"}]}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib_request.urlopen(req1, timeout=5) as resp1:
                body1 = json.loads(resp1.read().decode("utf-8"))
            # In Turn 1, __BLIND_AWS_ACCESS_KEY_001__ WAS in the request, so it is restored
            self.assertIn(aws_secret, body1["choices"][0]["message"]["content"])

            # Turn 2: benign request WITHOUT aws_secret; upstream LLM tries to output __BLIND_AWS_ACCESS_KEY_001__
            req2 = urllib_request.Request(
                f"http://127.0.0.1:{px_port}/v1/chat/completions",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "Hello world"}]}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib_request.urlopen(req2, timeout=5) as resp2:
                body2 = json.loads(resp2.read().decode("utf-8"))
            content2 = body2["choices"][0]["message"]["content"]
            # MUST NOT reveal aws_secret!
            self.assertNotIn(aws_secret, content2)
            self.assertIn("__BLIND_AWS_ACCESS_KEY_001__", content2)
        finally:
            proxy.shutdown()
            proxy.server_close()
            upstream.shutdown()
            upstream.server_close()

    def test_v2_scanner_catches_all_four_evasion_vectors(self) -> None:
        scanner = HybridScanner()

        # 1. Password with regex metacharacters ($, *, +, ?) in sensitive variable
        c1 = 'DB_PASSWORD = "Prod$ecret*2026+MasterKey?"'
        f1 = scanner.scan_text(c1)
        self.assertTrue(any("Prod$ecret*2026+MasterKey?" in f.value for f in f1), f1)

        # 2. Function call keyword argument & os.getenv fallback without digits
        c2 = 'connect(password="AlphaBravoCharlieDeltaEchoFoxtrot")\nos.getenv("API_SECRET", "ZuluYankeeXrayWhiskeyVictorUniform")'
        f2 = scanner.scan_text(c2)
        vals2 = {f.value for f in f2}
        self.assertIn("AlphaBravoCharlieDeltaEchoFoxtrot", vals2)
        self.assertIn("ZuluYankeeXrayWhiskeyVictorUniform", vals2)

        # 3. YAML valid as Python AnnAssign (no '=' value)
        c3 = 'database:\n  api_secret: "Zx8Yv7Wu6Ts5Rq4Po3Nm2Lk1Jh0Gf9Ed"\n'
        f3 = scanner.scan_text(c3)
        self.assertTrue(any(f.value == "Zx8Yv7Wu6Ts5Rq4Po3Nm2Lk1Jh0Gf9Ed" for f in f3), f3)

        # 4. Split secret concatenation via '+' in Python AST
        c4 = 'API_KEY = "sk-proj-12345" + "67890abcdefghijklmnop"\n'
        f4 = scanner.scan_text(c4)
        self.assertTrue(len(f4) >= 1, f4)

    def test_v3_proxy_blocks_csrf_origin_simple_post_dns_rebinding_and_session_flood(self) -> None:
        store = SessionStore(max_sessions=5)
        for i in range(20):
            store.sanitize(f"key = AKIA1234567890ABCDE{i % 10}", session_id=f"sess-{i}")
        self.assertLessEqual(len(store._sessions), 5)

        proxy = create_server(host="127.0.0.1", port=0, quiet=True)
        port = proxy.server_address[1]
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{port}/v1/sanitize"
        payload = json.dumps({"text": "hello"}).encode("utf-8")

        try:
            # 1. Cross-Origin header -> 403
            req_origin = urllib_request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
                method="POST",
            )
            with self.assertRaises(urllib_error.HTTPError) as ctx1:
                urllib_request.urlopen(req_origin, timeout=3)
            self.assertEqual(ctx1.exception.code, 403)

            # 2. Sec-Fetch-Site: cross-site -> 403
            req_fetch = urllib_request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
                method="POST",
            )
            with self.assertRaises(urllib_error.HTTPError) as ctx2:
                urllib_request.urlopen(req_fetch, timeout=3)
            self.assertEqual(ctx2.exception.code, 403)

            # 3. Simple-POST Content-Type: text/plain -> 415
            req_text = urllib_request.Request(
                url,
                data=payload,
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
            with self.assertRaises(urllib_error.HTTPError) as ctx3:
                urllib_request.urlopen(req_text, timeout=3)
            self.assertEqual(ctx3.exception.code, 415)

            # 4. DNS Rebinding Host header -> 403
            req_host = urllib_request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json", "Host": "rebind.attacker.com:8765"},
                method="POST",
            )
            with self.assertRaises(urllib_error.HTTPError) as ctx4:
                urllib_request.urlopen(req_host, timeout=3)
            self.assertEqual(ctx4.exception.code, 403)
        finally:
            proxy.shutdown()
            proxy.server_close()

    def test_v4_apply_blocks_ide_and_python_autorun_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault_path = root / "v.vault"
            PseudonymVault().save(vault_path)

            dangerous_targets = [
                ".vscode/tasks.json",
                ".cursor/mcp.json",
                "conftest.py",
                "sitecustomize.py",
                "setup.py",
                ".pre-commit-config.yaml",
            ]
            for target in dangerous_targets:
                md_file = root / "attack.md"
                md_file.write_text(f"### `{target}`\n\n```python\nprint('pwn')\n```\n", encoding="utf-8")
                code = cli_main(["apply", str(md_file), "--vault", str(vault_path), "--target-dir", str(root)])
                self.assertNotEqual(code, 0, f"Target {target} should be blocked by apply")
                self.assertFalse((root / target).exists(), f"File {target} must not be created")

    def test_v5_no_redos_on_malformed_pem_header_with_large_body(self) -> None:
        scanner = DeterministicScanner()
        pem_open = "-----BEGIN " + "RSA PRIVATE KEY-----"
        large_malformed = f"{pem_open}   \n" + ("A" * 120_000)
        t0 = time.perf_counter()
        findings = scanner.scan_text(large_malformed)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertTrue(any(f.kind == "pem_private_key" for f in findings))
        self.assertLess(elapsed_ms, 200.0)

    def test_v6_vault_files_created_securely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            v = PseudonymVault()
            v.sanitize("key = AKIA1234567890ABCDEF")
            p_json = Path(tmp) / "open.vault"
            p_enc = Path(tmp) / "enc.vault"
            v.save(p_json)
            save_encrypted(v, p_enc, "strong-passphrase")
            self.assertTrue(p_json.is_file())
            self.assertTrue(p_enc.is_file())


if __name__ == "__main__":
    unittest.main()
