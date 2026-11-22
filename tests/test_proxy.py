"""Unit and live HTTP integration tests for the local Blind AI proxy server."""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from blind_ai.proxy.server import BlindAIProxyServer, create_server  # noqa: E402


class LocalProxyServerTests(unittest.TestCase):
    """Validate all local HTTP proxy endpoints against a live ephemeral server."""

    server: BlindAIProxyServer
    thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server(host="127.0.0.1", port=0, quiet=True)
        port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            name="blind-ai-proxy-test",
            daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        *,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, Any]]:
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {}
        data: bytes | None = None

        if raw_body is not None:
            data = raw_body
            headers["Content-Type"] = "application/json"
        elif payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib_request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib_request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib_error.HTTPError as exc:
            body = json.loads(exc.read().decode("utf-8"))
            return exc.code, body

    def test_health_endpoint(self) -> None:
        status, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_sanitize_and_restore_roundtrip(self) -> None:
        secret = "sk-proj-FAKE1234567890abcdefghijklmnop"
        original = f"api_key = '{secret}'\nendpoint = '10.42.8.15'"

        status, san_body = self._request("POST", "/v1/sanitize", {"text": original})
        self.assertEqual(status, 200)
        self.assertIn("session_id", san_body)
        self.assertIn("sanitized_text", san_body)

        session_id = san_body["session_id"]
        sanitized = san_body["sanitized_text"]
        self.assertNotIn(secret, sanitized)
        self.assertNotIn("10.42.8.15", sanitized)
        self.assertIn("__BLIND_", sanitized)

        restore_status, res_body = self._request(
            "POST",
            "/v1/restore",
            {"session_id": session_id, "text": sanitized},
        )
        self.assertEqual(restore_status, 200)
        self.assertEqual(res_body["session_id"], session_id)
        self.assertEqual(res_body["restored_text"], original)

    def test_sanitize_reuses_session_placeholders(self) -> None:
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        status1, body1 = self._request(
            "POST",
            "/v1/sanitize",
            {"text": f"key_a = '{aws_key}'"},
        )
        self.assertEqual(status1, 200)
        session_id = body1["session_id"]

        status2, body2 = self._request(
            "POST",
            "/v1/sanitize",
            {"session_id": session_id, "text": f"key_b = '{aws_key}'"},
        )
        self.assertEqual(status2, 200)
        self.assertEqual(body2["session_id"], session_id)

        placeholder_1 = body1["sanitized_text"].split("'")[1]
        placeholder_2 = body2["sanitized_text"].split("'")[1]
        self.assertEqual(placeholder_1, placeholder_2)

    def test_proxy_echo_sanitizes_and_restores_locally(self) -> None:
        secret = "ghp_FakeToken1234567890ABCDEFGHIJ"
        original = f"# deploy note\ntoken = '{secret}'\n"

        status, body = self._request("POST", "/v1/proxy/echo", {"text": original})
        self.assertEqual(status, 200)
        self.assertIn("session_id", body)
        self.assertIn("sanitized_text", body)
        self.assertIn("restored_text", body)
        self.assertNotIn(secret, body["sanitized_text"])
        self.assertIn("__BLIND_", body["sanitized_text"])
        self.assertEqual(body["restored_text"], original)

    def test_session_isolation(self) -> None:
        secret = "sk-proj-ISOLATION9876543210abcdefghij"
        _, s1 = self._request("POST", "/v1/sanitize", {"text": f"k = '{secret}'"})
        _, s2 = self._request("POST", "/v1/sanitize", {"text": "clean = 'hello'"})

        self.assertNotEqual(s1["session_id"], s2["session_id"])
        status, res = self._request(
            "POST",
            "/v1/restore",
            {"session_id": s2["session_id"], "text": s1["sanitized_text"]},
        )
        self.assertEqual(status, 200)
        # Session 2 does not know session 1's placeholder, so secret is never leaked.
        self.assertEqual(res["restored_text"], s1["sanitized_text"])
        self.assertNotIn(secret, res["restored_text"])

    def test_bad_request_errors_400(self) -> None:
        # Malformed JSON
        status, body = self._request("POST", "/v1/sanitize", raw_body=b"{not-json")
        self.assertEqual(status, 400)
        self.assertIn("error", body)

        # Missing 'text' on /v1/sanitize
        status, _ = self._request("POST", "/v1/sanitize", {})
        self.assertEqual(status, 400)

        # Non-string 'text' on /v1/sanitize
        status, _ = self._request("POST", "/v1/sanitize", {"text": 12345})
        self.assertEqual(status, 400)

        # Empty session_id on /v1/sanitize
        status, _ = self._request("POST", "/v1/sanitize", {"text": "ok", "session_id": ""})
        self.assertEqual(status, 400)

        # Missing fields on /v1/restore
        status, _ = self._request("POST", "/v1/restore", {"text": "abc"})
        self.assertEqual(status, 400)
        status, _ = self._request("POST", "/v1/restore", {"session_id": "abc"})
        self.assertEqual(status, 400)

        # Invalid 'text' on /v1/proxy/echo
        status, _ = self._request("POST", "/v1/proxy/echo", {"text": ["bad"]})
        self.assertEqual(status, 400)

    def test_not_found_errors_404(self) -> None:
        status, body = self._request(
            "POST",
            "/v1/restore",
            {"session_id": "non-existent-session", "text": "__BLIND_OPENAI_API_KEY_001__"},
        )
        self.assertEqual(status, 404)
        self.assertIn("error", body)

        status_get, _ = self._request("GET", "/does-not-exist")
        self.assertEqual(status_get, 404)

        status_post, _ = self._request("POST", "/v1/does-not-exist", {"text": "x"})
        self.assertEqual(status_post, 404)


if __name__ == "__main__":
    unittest.main()
