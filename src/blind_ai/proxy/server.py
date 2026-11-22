"""Local HTTP Proxy/Gateway for Blind AI (Layer 4).

Uses only the Python 3.12 standard library. Exposes local endpoints for
health checking, reversible session-scoped sanitization, restoration, and
offline echo verification without performing any external network requests.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
import threading
from typing import Any
from urllib.parse import urlsplit

from blind_ai.core.contextual import HybridScanner
from blind_ai.core.vault import PseudonymVault

MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MiB safety limit for local requests


class SessionStore:
    """Thread-safe in-memory mapping from ``session_id`` to :class:`PseudonymVault`."""

    def __init__(
        self,
        *,
        scanner_factory: Callable[[], Any] = HybridScanner,
    ) -> None:
        self._scanner_factory = scanner_factory
        self._lock = threading.Lock()
        self._sessions: dict[str, PseudonymVault] = {}

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
        """Restore placeholders in *text* for *session_id*, or return None if unknown."""
        with self._lock:
            vault = self._sessions.get(session_id)
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
        """Return True if *session_id* currently exists in memory."""
        with self._lock:
            return session_id in self._sessions

    def _get_or_create_unlocked(self, session_id: str | None) -> PseudonymVault:
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
    ) -> None:
        self.session_store = session_store or SessionStore()
        self.quiet = quiet
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
        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/v1/sanitize":
            self._handle_sanitize()
            return
        if path == "/v1/restore":
            self._handle_restore()
            return
        if path == "/v1/proxy/echo":
            self._handle_proxy_echo()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

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

    def _validate_optional_session_id(self, payload: dict[str, Any]) -> str | None | object:
        if "session_id" not in payload or payload["session_id"] is None:
            return None
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

        if content_length < 0 or content_length > MAX_BODY_BYTES:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Request body length is out of allowed bounds."},
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

    def _send_json(self, status: HTTPStatus | int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


_INVALID = object()


def create_server(
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    scanner_factory: Callable[[], Any] = HybridScanner,
    quiet: bool = False,
) -> BlindAIProxyServer:
    """Instantiate a configured :class:`BlindAIProxyServer`."""
    store = SessionStore(scanner_factory=scanner_factory)
    return BlindAIProxyServer((host, port), session_store=store, quiet=quiet)


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
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for launching the local Blind AI HTTP server."""
    args = build_arg_parser().parse_args(argv)
    server = create_server(host=args.host, port=args.port, quiet=args.quiet)
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
