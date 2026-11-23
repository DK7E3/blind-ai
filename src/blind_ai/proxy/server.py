"""Local HTTP Proxy/Gateway for Blind AI (Layer 4).

Uses only the Python 3.12 standard library. Exposes local endpoints for
health checking, reversible session-scoped sanitization, restoration,
offline echo verification, and an OpenAI-compatible ``/v1/chat/completions``
gateway (JSON and SSE streaming) with optional Bearer auth, payload size
limits, and TTL session expiration.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit
import uuid

from blind_ai.core.contextual import HybridScanner
from blind_ai.core.secure_vault import TTLSessionStore
from blind_ai.core.vault import PseudonymVault
from blind_ai.proxy.openai_gateway import GatewayError, handle_chat_completions

MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MiB safety limit for local requests


class SessionStore:
    """Thread-safe in-memory mapping from ``session_id`` to :class:`PseudonymVault`.

    When *ttl_seconds* is provided, delegates session storage and expiration to
    :class:`~blind_ai.core.secure_vault.TTLSessionStore`.
    """

    def __init__(
        self,
        *,
        scanner_factory: Callable[[], Any] = HybridScanner,
        ttl_seconds: float | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._scanner_factory = scanner_factory
        self._lock = threading.Lock()
        self._ttl_store: TTLSessionStore | None = (
            TTLSessionStore(ttl_seconds, clock=clock or time.monotonic)
            if ttl_seconds is not None
            else None
        )
        self._sessions: dict[str, PseudonymVault] = {}

    @property
    def ttl_seconds(self) -> float | None:
        """Return the configured TTL in seconds, or ``None`` if sessions do not expire."""
        return self._ttl_store.ttl_seconds if self._ttl_store is not None else None

    def sanitize(
        self,
        text: str,
        session_id: str | None = None,
    ) -> tuple[str, str]:
        """Sanitize *text* within *session_id* (creating a vault if needed)."""
        with self._lock:
            vault = self._get_or_create_unlocked(session_id)
            sanitized = vault.sanitize(text)
            return vault.session_id, sanitized

    def restore(self, session_id: str, text: str) -> str | None:
        """Restore placeholders in *text* for *session_id*, or return None if unknown/expired."""
        with self._lock:
            vault = self._get_unlocked(session_id)
            if vault is None:
                return None
            return vault.restore(text)

    def echo(
        self,
        text: str,
        session_id: str | None = None,
    ) -> tuple[str, str, str]:
        """Sanitize *text*, simulate a local placeholder-preserving echo, and restore."""
        with self._lock:
            vault = self._get_or_create_unlocked(session_id)
            sanitized = vault.sanitize(text)
            # Local-only echo simulation: no external network call; placeholders stay intact.
            echoed_payload = sanitized
            restored = vault.restore(echoed_payload)
            return vault.session_id, sanitized, restored

    def has_session(self, session_id: str) -> bool:
        """Return True if *session_id* currently exists and is active in memory."""
        with self._lock:
            if self._ttl_store is not None:
                return self._ttl_store.get(session_id) is not None
            return session_id in self._sessions

    def _get_unlocked(self, session_id: str) -> PseudonymVault | None:
        if self._ttl_store is not None:
            return self._ttl_store.get(session_id)
        return self._sessions.get(session_id)

    def _get_or_create_unlocked(self, session_id: str | None) -> PseudonymVault:
        if self._ttl_store is not None:
            sid = session_id if session_id is not None else uuid.uuid4().hex
            existing = self._ttl_store.get(sid)
            if existing is not None:
                return existing
            return self._ttl_store.get_or_create(sid, scanner=self._scanner_factory())

        if session_id is not None:
            existing = self._sessions.get(session_id)
            if existing is not None:
                return existing
            vault = PseudonymVault(
                session_id=session_id,
                scanner=self._scanner_factory(),
            )
            self._sessions[vault.session_id] = vault
            return vault

        vault = PseudonymVault(scanner=self._scanner_factory())
        self._sessions[vault.session_id] = vault
        return vault


class BlindAIProxyServer(ThreadingHTTPServer):
    """Multi-threaded local HTTP server carrying an in-memory :class:`SessionStore`."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        session_store: SessionStore | None = None,
        quiet: bool = False,
        upstream_url: str | None = None,
        upstream_api_key: str | None = None,
        auth_token: str | None = None,
        max_body_bytes: int = MAX_BODY_BYTES,
        default_session_id: str | None = "default",
    ) -> None:
        if (
            isinstance(max_body_bytes, bool)
            or not isinstance(max_body_bytes, int)
            or max_body_bytes <= 0
        ):
            raise ValueError("max_body_bytes must be a positive integer.")
        if default_session_id is not None and (
            not isinstance(default_session_id, str) or not default_session_id.strip()
        ):
            raise ValueError("default_session_id must be None or a non-empty string.")
        self.session_store = session_store or SessionStore()
        self.quiet = quiet
        self.upstream_url = upstream_url
        self.upstream_api_key = upstream_api_key
        self.auth_token = auth_token
        self.max_body_bytes = max_body_bytes
        self.default_session_id = (
            default_session_id.strip() if default_session_id is not None else None
        )
        super().__init__(server_address, BlindAIRequestHandler)


class BlindAIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the local Blind AI proxy endpoints."""

    server: BlindAIProxyServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        if self.server.quiet:
            return
        super().log_message(format, *args)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path.startswith("/v1/") and not self._check_auth():
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path.startswith("/v1/") and not self._check_auth():
            return
        if path == "/v1/sanitize":
            self._handle_sanitize()
            return
        if path == "/v1/restore":
            self._handle_restore()
            return
        if path == "/v1/proxy/echo":
            self._handle_proxy_echo()
            return
        if path == "/v1/chat/completions":
            self._handle_chat_completions()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

    def _check_auth(self) -> bool:
        expected = self.server.auth_token
        if not expected:
            return True
        auth_header = self.headers.get("Authorization")
        if not auth_header:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Unauthorized: valid Bearer token required."},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return False
        scheme, sep, token = auth_header.partition(" ")
        if (
            not sep
            or scheme.lower() != "bearer"
            or not token
            or not hmac.compare_digest(token, expected)
        ):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Unauthorized: valid Bearer token required."},
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return False
        return True

    def _handle_sanitize(self) -> None:
        payload = self._read_json_object()
        if payload is None:
            return

        text = payload.get("text")
        if not isinstance(text, str):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Field 'text' is required and must be a string."},
            )
            return

        session_id = self._validate_optional_session_id(payload)
        if session_id is _INVALID:
            return

        resolved_session_id, sanitized_text = self.server.session_store.sanitize(
            text,
            session_id=session_id,
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "session_id": resolved_session_id,
                "sanitized_text": sanitized_text,
            },
        )

    def _handle_restore(self) -> None:
        payload = self._read_json_object()
        if payload is None:
            return

        session_id = payload.get("session_id")
        if session_id is None:
            header_sid = self.headers.get("X-Blind-AI-Session-Id")
            if header_sid is not None and header_sid.strip():
                session_id = header_sid.strip()
        if not isinstance(session_id, str) or not session_id.strip():
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Field 'session_id' is required and must be a non-empty string."},
            )
            return

        text = payload.get("text")
        if not isinstance(text, str):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Field 'text' is required and must be a string."},
            )
            return

        restored_text = self.server.session_store.restore(session_id, text)
        if restored_text is None:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": f"Unknown session_id: {session_id}"},
            )
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "session_id": session_id,
                "restored_text": restored_text,
            },
        )

    def _handle_proxy_echo(self) -> None:
        payload = self._read_json_object()
        if payload is None:
            return

        text = payload.get("text")
        if not isinstance(text, str):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Field 'text' is required and must be a string."},
            )
            return

        session_id = self._validate_optional_session_id(payload)
        if session_id is _INVALID:
            return

        resolved_session_id, sanitized_text, restored_text = self.server.session_store.echo(
            text,
            session_id=session_id,
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "session_id": resolved_session_id,
                "sanitized_text": sanitized_text,
                "restored_text": restored_text,
            },
        )

    def _handle_chat_completions(self) -> None:
        payload = self._read_json_object()
        if payload is None:
            return

        session_id = self._validate_optional_session_id(
            payload,
            fallback_session_id=self.server.default_session_id,
        )
        if session_id is _INVALID:
            return

        try:
            resolved_session_id, is_stream, result = handle_chat_completions(
                payload,
                self.server.session_store,
                session_id=session_id,
                upstream_url=self.server.upstream_url,
                upstream_api_key=self.server.upstream_api_key,
            )
        except GatewayError as exc:
            self._send_json(exc.status, {"error": exc.message})
            return

        if is_stream:
            assert isinstance(result, Iterator)
            self.send_response(int(HTTPStatus.OK))
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Blind-AI-Session-Id", resolved_session_id)
            self.end_headers()
            for event_bytes in result:
                self.wfile.write(event_bytes)
                self.wfile.flush()
            return

        assert isinstance(result, dict)
        self._send_json(
            HTTPStatus.OK,
            result,
            extra_headers={"X-Blind-AI-Session-Id": resolved_session_id},
        )

    def _validate_optional_session_id(
        self,
        payload: dict[str, Any],
        *,
        fallback_session_id: str | None = None,
    ) -> str | None | object:
        if "session_id" not in payload or payload["session_id"] is None:
            header_sid = self.headers.get("X-Blind-AI-Session-Id")
            if header_sid is not None and header_sid.strip():
                return header_sid.strip()
            return fallback_session_id
        session_id = payload["session_id"]
        if not isinstance(session_id, str) or not session_id.strip():
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Optional field 'session_id' must be a non-empty string."},
            )
            return _INVALID
        return session_id

    def _read_json_object(self) -> dict[str, Any] | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Missing Content-Length header."},
            )
            return None

        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid Content-Length header."},
            )
            return None

        if content_length < 0:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Request body length must be non-negative."},
            )
            return None

        if content_length > self.server.max_body_bytes:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": (
                        f"Request body exceeds maximum allowed size of "
                        f"{self.server.max_body_bytes} bytes."
                    )
                },
            )
            return None

        raw_body = self.rfile.read(content_length)
        try:
            decoded = raw_body.decode("utf-8")
            parsed = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Request body must be valid UTF-8 JSON."},
            )
            return None

        if not isinstance(parsed, dict):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "JSON payload must be an object."},
            )
            return None

        return parsed

    def _send_json(
        self,
        status: HTTPStatus | int,
        body: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)


_INVALID = object()


def create_server(
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    scanner_factory: Callable[[], Any] = HybridScanner,
    quiet: bool = False,
    upstream_url: str | None = None,
    upstream_api_key: str | None = None,
    auth_token: str | None = None,
    max_body_bytes: int = MAX_BODY_BYTES,
    session_ttl: float | None = None,
    clock: Callable[[], float] | None = None,
    default_session_id: str | None = "default",
) -> BlindAIProxyServer:
    """Instantiate a configured :class:`BlindAIProxyServer`."""
    store = SessionStore(
        scanner_factory=scanner_factory,
        ttl_seconds=session_ttl,
        clock=clock,
    )
    resolved_upstream_key = (
        upstream_api_key
        if upstream_api_key is not None
        else os.environ.get("BLIND_AI_UPSTREAM_API_KEY")
    )
    return BlindAIProxyServer(
        (host, port),
        session_store=store,
        quiet=quiet,
        upstream_url=upstream_url,
        upstream_api_key=resolved_upstream_key,
        auth_token=auth_token,
        max_body_bytes=max_body_bytes,
        default_session_id=default_session_id,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for ``python -m blind_ai.proxy.server``."""
    parser = argparse.ArgumentParser(
        prog="blind_ai.proxy.server",
        description="Run the local Blind AI HTTP proxy/gateway server.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Local host interface to bind (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="TCP port to listen on (default: 8765).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-request access logs.",
    )
    parser.add_argument(
        "--upstream-url",
        default=None,
        help="Optional local OpenAI-compatible upstream base or endpoint URL.",
    )
    parser.add_argument(
        "--upstream-api-key",
        default=os.environ.get("BLIND_AI_UPSTREAM_API_KEY"),
        help="Optional upstream API key sent as Authorization: Bearer (or BLIND_AI_UPSTREAM_API_KEY).",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Optional Bearer token required on all /v1/* endpoints.",
    )
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=MAX_BODY_BYTES,
        help=f"Maximum allowed HTTP request body size in bytes (default: {MAX_BODY_BYTES}).",
    )
    parser.add_argument(
        "--session-ttl",
        type=float,
        default=None,
        help="Optional session inactivity TTL in seconds.",
    )
    parser.add_argument(
        "--default-session-id",
        default="default",
        help="Default session ID for /v1/chat/completions when omitted from payload and header (default: default).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for launching the local Blind AI HTTP server."""
    args = build_arg_parser().parse_args(argv)
    default_sid = args.default_session_id if args.default_session_id and args.default_session_id.strip() else None
    server = create_server(
        host=args.host,
        port=args.port,
        quiet=args.quiet,
        upstream_url=args.upstream_url,
        upstream_api_key=args.upstream_api_key,
        auth_token=args.auth_token,
        max_body_bytes=args.max_body_bytes,
        session_ttl=args.session_ttl,
        default_session_id=default_sid,
    )
    bound_host, bound_port = server.server_address[:2]
    print(
        f"Blind AI local proxy listening on http://{bound_host}:{bound_port}",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
