"""Unit and live HTTP integration tests for OpenAI gateway, StreamRestorer, and hardening."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from blind_ai.core.vault import PseudonymVault  # noqa: E402
from blind_ai.proxy.openai_gateway import (  # noqa: E402
    StreamRestorer,
    resolve_upstream_endpoint,
)
from blind_ai.proxy.server import (  # noqa: E402
    BlindAIProxyServer,
    SessionStore,
    build_arg_parser,
    create_server,
)


def _start_server(server: ThreadingHTTPServer, name: str) -> tuple[str, threading.Thread]:
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", thread


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _http_json(
    url: str,
    method: str = "POST",
    payload: Any = None,
    *,
    headers: dict[str, str] | None = None,
    raw_body: bytes | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    req_headers: dict[str, str] = dict(headers or {})
    data: bytes | None = None
    if raw_body is not None:
        data = raw_body
        req_headers.setdefault("Content-Type", "application/json")
    elif payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib_request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body, dict(resp.headers.items())
    except urllib_error.HTTPError as exc:
        body = json.loads(exc.read().decode("utf-8"))
        return exc.code, body, dict(exc.headers.items())


def _http_sse(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, list[str], dict[str, str]]:
    req_headers = {"Content-Type": "application/json", **dict(headers or {})}
    data = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(url, data=data, headers=req_headers, method="POST")
    with urllib_request.urlopen(req, timeout=5) as resp:
        raw_text = resp.read().decode("utf-8")
        content_type = resp.headers.get("Content-Type", "")
        events = [
            line[5:].strip()
            for line in raw_text.splitlines()
            if line.startswith("data:")
        ]
        return resp.status, content_type, events, dict(resp.headers.items())


class StreamRestorerUnitTests(unittest.TestCase):
    """Unit tests for incremental placeholder restoration across arbitrary chunk splits."""

    def setUp(self) -> None:
        self.vault = PseudonymVault(session_id="stream-test")
        self.secret_a = "sk-proj-STREAM1234567890abcdefghijkl"
        self.secret_b = "10.42.99.7"
        self.ph_a = self.vault.get_or_create_placeholder(self.secret_a, "OPENAI_API_KEY")
        self.ph_b = self.vault.get_or_create_placeholder(self.secret_b, "IPV4_ADDRESS")

    def test_split_in_two_chunks_at_every_position(self) -> None:
        full_text = f"key={self.ph_a}; end"
        expected = f"key={self.secret_a}; end"

        for split_idx in range(1, len(full_text)):
            restorer = StreamRestorer(self.vault)
            out = restorer.feed(full_text[:split_idx])
            out += restorer.feed(full_text[split_idx:])
            out += restorer.flush()
            self.assertEqual(out, expected, f"Failed at split_idx={split_idx}")

    def test_split_in_three_chunks_inside_placeholder(self) -> None:
        # Split across prefix "__BL", body "IND_OPENAI_API_KEY_001_", and closing "_"
        chunks = [
            "prefix __BL",
            f"IND_{self.ph_a[len('__BLIND_'):-1]}",
            "_ suffix",
        ]
        restorer = StreamRestorer(self.vault.restore)
        out = "".join(restorer.feed(chunk) for chunk in chunks) + restorer.flush()
        self.assertEqual(out, f"prefix {self.secret_a} suffix")

    def test_false_prefixes_are_preserved_and_not_stalled(self) -> None:
        restorer = StreamRestorer(self.vault)
        out1 = restorer.feed("__")
        self.assertEqual(out1, "")
        out2 = restorer.feed("not_blind ")
        self.assertEqual(out2, "__not_blind ")
        out3 = restorer.feed("__BLIND_lower ")
        self.assertEqual(out3, "__BLIND_lower ")
        out4 = restorer.feed("__BLIND_UNFINISHED ")
        self.assertEqual(out4, "__BLIND_UNFINISHED ")
        self.assertEqual(restorer.flush(), "")

    def test_adjacent_placeholders_split_across_chunks(self) -> None:
        combined = f"{self.ph_a}{self.ph_b}"
        expected = f"{self.secret_a}{self.secret_b}"

        # Split into 3 arbitrary chunks spanning both adjacent placeholders
        c1 = combined[: len(self.ph_a) - 3]
        c2 = combined[len(self.ph_a) - 3 : len(self.ph_a) + 5]
        c3 = combined[len(self.ph_a) + 5 :]

        restorer = StreamRestorer({self.ph_a: self.secret_a, self.ph_b: self.secret_b})
        out = restorer.feed(c1) + restorer.feed(c2) + restorer.feed(c3) + restorer.flush()
        self.assertEqual(out, expected)

    def test_flush_emits_trailing_partial_fragments(self) -> None:
        restorer = StreamRestorer(self.vault)
        self.assertEqual(restorer.feed("hello __BL"), "hello ")
        self.assertEqual(restorer.flush(), "__BL")
        self.assertEqual(restorer.flush(), "")

        self.assertEqual(restorer.feed("tail __BLIND_PARTIAL_001"), "tail ")
        self.assertEqual(restorer.flush(), "__BLIND_PARTIAL_001")


class _MockUpstreamServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int]) -> None:
        self.received_requests: list[dict[str, Any]] = []
        self.received_headers: list[dict[str, str]] = []
        super().__init__(server_address, _MockUpstreamHandler)


class _MockUpstreamHandler(BaseHTTPRequestHandler):
    server: _MockUpstreamServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        self.server.received_requests.append(body)
        self.server.received_headers.append(dict(self.headers.items()))

        last_msg = body["messages"][-1]
        user_content = last_msg.get("content") or ""
        reply_text = f"Upstream saw: {user_content}"
        model = body.get("model", "mock-model")
        inbound_tool_calls = last_msg.get("tool_calls")

        if body.get("stream"):
            self.send_response(int(HTTPStatus.OK))
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()

            if isinstance(inbound_tool_calls, list) and inbound_tool_calls:
                tc_args = inbound_tool_calls[0]["function"]["arguments"]
                for idx in range(0, len(tc_args), 5):
                    piece = tc_args[idx : idx + 5]
                    chunk = {
                        "id": "chatcmpl-upstream-sse-tc",
                        "object": "chat.completion.chunk",
                        "created": 1700000000,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call_1",
                                            "type": "function",
                                            "function": {
                                                "name": "deploy_app",
                                                "arguments": piece,
                                            },
                                        }
                                    ]
                                },
                                "finish_reason": None,
                            }
                        ],
                    }
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                    self.wfile.flush()
            else:
                # Intentionally slice into small 5-char chunks to split placeholders across 3+ events
                for idx in range(0, len(reply_text), 5):
                    piece = reply_text[idx : idx + 5]
                    chunk = {
                        "id": "chatcmpl-upstream-sse",
                        "object": "chat.completion.chunk",
                        "created": 1700000000,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": piece},
                                "finish_reason": None,
                            }
                        ],
                    }
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                    self.wfile.flush()

            stop_chunk = {
                "id": "chatcmpl-upstream-sse",
                "object": "chat.completion.chunk",
                "created": 1700000000,
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            self.wfile.write(f"data: {json.dumps(stop_chunk)}\n\n".encode("utf-8"))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return

        message_obj: dict[str, Any] = {"role": "assistant", "content": reply_text}
        if isinstance(inbound_tool_calls, list) and inbound_tool_calls:
            message_obj["tool_calls"] = inbound_tool_calls

        resp_payload = {
            "id": "chatcmpl-upstream-json",
            "object": "chat.completion",
            "created": 1700000000,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": message_obj,
                    "finish_reason": "stop",
                }
            ],
        }
        encoded = json.dumps(resp_payload).encode("utf-8")
        self.send_response(int(HTTPStatus.OK))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class OpenAIGatewayIntegrationTests(unittest.TestCase):
    """Live HTTP integration tests for /v1/chat/completions, auth, 413, TTL, and CLI."""

    def test_local_echo_json_and_sse(self) -> None:
        server = create_server(host="127.0.0.1", port=0, quiet=True)
        base_url, thread = _start_server(server, "blind-ai-local-echo")
        try:
            secret = "sk-proj-LOCAL1234567890abcdefghijklm"
            prompt = f"Use token {secret} on 10.20.30.40"

            # JSON local echo
            status, body, headers = _http_json(
                f"{base_url}/v1/chat/completions",
                payload={
                    "model": "gpt-local-test",
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["object"], "chat.completion")
            self.assertEqual(body["model"], "gpt-local-test")
            self.assertEqual(body["choices"][0]["message"]["content"], prompt)
            self.assertIn("X-Blind-AI-Session-Id", headers)

            # SSE local echo
            sse_status, content_type, events, _ = _http_sse(
                f"{base_url}/v1/chat/completions",
                payload={
                    "model": "gpt-local-test",
                    "stream": True,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            self.assertEqual(sse_status, 200)
            self.assertIn("text/event-stream", content_type)
            self.assertEqual(events[-1], "[DONE]")

            reconstructed = ""
            for raw_event in events[:-1]:
                chunk = json.loads(raw_event)
                delta = chunk["choices"][0]["delta"]
                reconstructed += delta.get("content", "")
            self.assertEqual(reconstructed, prompt)
        finally:
            _stop_server(server, thread)

    def test_upstream_mock_json_and_sse_masks_outbound_and_restores_inbound(self) -> None:
        upstream = _MockUpstreamServer(("127.0.0.1", 0))
        upstream_url, upstream_thread = _start_server(upstream, "mock-upstream")
        proxy = create_server(
            host="127.0.0.1",
            port=0,
            quiet=True,
            upstream_url=upstream_url,
        )
        proxy_url, proxy_thread = _start_server(proxy, "blind-ai-upstream-proxy")

        try:
            secret = "ghp_UpstreamSecret1234567890ABCDEFGH"
            ip_addr = "192.168.50.12"
            prompt = f"Deploy with {secret} to {ip_addr}"

            # 1) JSON roundtrip through upstream
            status, body, _ = _http_json(
                f"{proxy_url}/v1/chat/completions",
                payload={
                    "model": "test-upstream",
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["choices"][0]["message"]["content"], f"Upstream saw: {prompt}")

            # Verify upstream NEVER saw raw secrets
            self.assertEqual(len(upstream.received_requests), 1)
            sent_to_upstream = upstream.received_requests[0]["messages"][0]["content"]
            self.assertNotIn(secret, sent_to_upstream)
            self.assertNotIn(ip_addr, sent_to_upstream)
            self.assertIn("__BLIND_", sent_to_upstream)

            # 2) SSE streaming roundtrip through upstream (5-char chunks split placeholders!)
            sse_status, content_type, events, _ = _http_sse(
                f"{proxy_url}/v1/chat/completions",
                payload={
                    "model": "test-upstream",
                    "stream": True,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            self.assertEqual(sse_status, 200)
            self.assertIn("text/event-stream", content_type)
            self.assertEqual(events[-1], "[DONE]")

            reconstructed = ""
            for raw_event in events[:-1]:
                chunk = json.loads(raw_event)
                reconstructed += chunk["choices"][0]["delta"].get("content", "")

            self.assertEqual(reconstructed, f"Upstream saw: {prompt}")
            self.assertEqual(len(upstream.received_requests), 2)
            sent_stream_upstream = upstream.received_requests[1]["messages"][0]["content"]
            self.assertNotIn(secret, sent_stream_upstream)
            self.assertNotIn(ip_addr, sent_stream_upstream)
            self.assertIn("__BLIND_", sent_stream_upstream)
        finally:
            _stop_server(proxy, proxy_thread)
            _stop_server(upstream, upstream_thread)

    def test_bearer_auth_hardening_and_public_health(self) -> None:
        token = "super-secret-bearer-token-2026"
        server = create_server(host="127.0.0.1", port=0, quiet=True, auth_token=token)
        base_url, thread = _start_server(server, "blind-ai-auth")
        try:
            # /health remains public
            status, body, _ = _http_json(f"{base_url}/health", method="GET")
            self.assertEqual(status, 200)
            self.assertEqual(body, {"status": "ok"})

            # Missing Authorization header -> 401 on /v1/*
            for endpoint, payload in (
                ("/v1/sanitize", {"text": "hello"}),
                ("/v1/proxy/echo", {"text": "hello"}),
                ("/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}]}),
            ):
                s_missing, _, _ = _http_json(f"{base_url}{endpoint}", payload=payload)
                self.assertEqual(s_missing, 401, f"Expected 401 without token on {endpoint}")

                s_wrong, _, _ = _http_json(
                    f"{base_url}{endpoint}",
                    payload=payload,
                    headers={"Authorization": "Bearer wrong-token"},
                )
                self.assertEqual(s_wrong, 401, f"Expected 401 with wrong token on {endpoint}")

                s_ok, _, _ = _http_json(
                    f"{base_url}{endpoint}",
                    payload=payload,
                    headers={"Authorization": f"Bearer {token}"},
                )
                self.assertEqual(s_ok, 200, f"Expected 200 with valid token on {endpoint}")
        finally:
            _stop_server(server, thread)

    def test_payload_size_limit_returns_413(self) -> None:
        server = create_server(host="127.0.0.1", port=0, quiet=True, max_body_bytes=64)
        base_url, thread = _start_server(server, "blind-ai-413")
        try:
            # Small payload succeeds
            s_ok, _, _ = _http_json(f"{base_url}/v1/sanitize", payload={"text": "short"})
            self.assertEqual(s_ok, 200)

            # Oversized payload returns HTTP 413
            s_large, body_large, _ = _http_json(
                f"{base_url}/v1/sanitize",
                payload={"text": "A" * 200},
            )
            self.assertEqual(s_large, 413)
            self.assertIn("error", body_large)

            # Oversized payload on /v1/chat/completions also returns HTTP 413
            s_chat, _, _ = _http_json(
                f"{base_url}/v1/chat/completions",
                payload={"messages": [{"role": "user", "content": "B" * 200}]},
            )
            self.assertEqual(s_chat, 413)
        finally:
            _stop_server(server, thread)

    def test_ttl_session_expiration(self) -> None:
        now = [100.0]

        def fake_clock() -> float:
            return now[0]

        server = create_server(
            host="127.0.0.1",
            port=0,
            quiet=True,
            session_ttl=10.0,
            clock=fake_clock,
        )
        base_url, thread = _start_server(server, "blind-ai-ttl")
        try:
            secret = "sk-proj-TTLTEST1234567890abcdefghijk"
            status, san_body, _ = _http_json(
                f"{base_url}/v1/sanitize",
                payload={"text": f"token={secret}"},
            )
            self.assertEqual(status, 200)
            session_id = san_body["session_id"]
            sanitized = san_body["sanitized_text"]
            self.assertTrue(server.session_store.has_session(session_id))

            # Advance clock within TTL -> still active
            now[0] += 5.0
            res_status, res_body, _ = _http_json(
                f"{base_url}/v1/restore",
                payload={"session_id": session_id, "text": sanitized},
            )
            self.assertEqual(res_status, 200)
            self.assertEqual(res_body["restored_text"], f"token={secret}")

            # Advance clock past TTL -> expired -> 404
            now[0] += 11.0
            self.assertFalse(server.session_store.has_session(session_id))
            exp_status, _, _ = _http_json(
                f"{base_url}/v1/restore",
                payload={"session_id": session_id, "text": sanitized},
            )
            self.assertEqual(exp_status, 404)
        finally:
            _stop_server(server, thread)

    def test_cli_arg_parser_and_upstream_endpoint_resolution(self) -> None:
        parser = build_arg_parser()
        args = parser.parse_args(
            [
                "--host",
                "127.0.0.1",
                "--port",
                "9000",
                "--quiet",
                "--upstream-url",
                "http://127.0.0.1:11434",
                "--auth-token",
                "tok-123",
                "--max-body-bytes",
                "4096",
                "--session-ttl",
                "120.5",
            ]
        )
        self.assertEqual(args.upstream_url, "http://127.0.0.1:11434")
        self.assertEqual(args.auth_token, "tok-123")
        self.assertEqual(args.max_body_bytes, 4096)
        self.assertEqual(args.session_ttl, 120.5)

        self.assertEqual(
            resolve_upstream_endpoint("http://127.0.0.1:8000"),
            "http://127.0.0.1:8000/v1/chat/completions",
        )
        self.assertEqual(
            resolve_upstream_endpoint("http://127.0.0.1:8000/v1"),
            "http://127.0.0.1:8000/v1/chat/completions",
        )
        self.assertEqual(
            resolve_upstream_endpoint("http://127.0.0.1:8000/v1/chat/completions"),
            "http://127.0.0.1:8000/v1/chat/completions",
        )

        # Direct SessionStore TTL check
        t = [0.0]
        store = SessionStore(ttl_seconds=5.0, clock=lambda: t[0])
        sid, san = store.sanitize("ip=10.1.2.3")
        self.assertTrue(store.has_session(sid))
        t[0] = 6.0
        self.assertFalse(store.has_session(sid))
        self.assertIsNone(store.restore(sid, san))

    def test_upstream_api_key_and_tool_calls_json_and_sse(self) -> None:
        upstream = _MockUpstreamServer(("127.0.0.1", 0))
        upstream_url, upstream_thread = _start_server(upstream, "mock-upstream-tc")
        upstream_key = "up-secret-key-999"
        proxy = create_server(
            host="127.0.0.1",
            port=0,
            quiet=True,
            upstream_url=upstream_url,
            upstream_api_key=upstream_key,
        )
        proxy_url, proxy_thread = _start_server(proxy, "blind-ai-tc-proxy")

        try:
            secret = "ghp_ToolCallSecret1234567890ABCDEFGH"
            ip_addr = "10.99.88.77"
            raw_args = json.dumps({"token": secret, "host": ip_addr})
            tool_call_msg = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "deploy_app",
                            "arguments": raw_args,
                        },
                    }
                ],
            }

            # 1) JSON roundtrip with tool_calls and upstream_api_key
            status, body, _ = _http_json(
                f"{proxy_url}/v1/chat/completions",
                payload={
                    "model": "test-tc",
                    "messages": [tool_call_msg],
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(
                upstream.received_headers[0].get("Authorization"),
                f"Bearer {upstream_key}",
            )
            sent_tc_args = upstream.received_requests[0]["messages"][0]["tool_calls"][0][
                "function"
            ]["arguments"]
            self.assertNotIn(secret, sent_tc_args)
            self.assertNotIn(ip_addr, sent_tc_args)
            self.assertIn("__BLIND_", sent_tc_args)

            restored_tc_args = body["choices"][0]["message"]["tool_calls"][0]["function"][
                "arguments"
            ]
            self.assertEqual(restored_tc_args, raw_args)

            # 2) SSE roundtrip with delta.tool_calls and env var BLIND_AI_UPSTREAM_API_KEY
            proxy.upstream_api_key = None
            with patch.dict(
                os.environ, {"BLIND_AI_UPSTREAM_API_KEY": "env-upstream-key-777"}
            ):
                sse_status, _, events, _ = _http_sse(
                    f"{proxy_url}/v1/chat/completions",
                    payload={
                        "model": "test-tc",
                        "stream": True,
                        "messages": [tool_call_msg],
                    },
                )
            self.assertEqual(sse_status, 200)
            self.assertEqual(
                upstream.received_headers[1].get("Authorization"),
                "Bearer env-upstream-key-777",
            )
            self.assertEqual(events[-1], "[DONE]")

            reconstructed_args = ""
            for raw_event in events[:-1]:
                chunk = json.loads(raw_event)
                delta = chunk["choices"][0]["delta"]
                for tc in delta.get("tool_calls", []):
                    reconstructed_args += tc.get("function", {}).get("arguments", "")
            self.assertEqual(reconstructed_args, raw_args)

            # 3) CLI arg parser supports --upstream-api-key
            parsed_args = build_arg_parser().parse_args(
                ["--upstream-api-key", "cli-up-key"]
            )
            self.assertEqual(parsed_args.upstream_api_key, "cli-up-key")
        finally:
            _stop_server(proxy, proxy_thread)
            _stop_server(upstream, upstream_thread)


if __name__ == "__main__":
    unittest.main()
