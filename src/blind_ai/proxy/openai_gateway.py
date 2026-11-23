"""OpenAI-compatible /v1/chat/completions gateway and SSE StreamRestorer for Blind AI.

Uses only the Python 3.12 standard library. Sanitizes outbound chat messages
using a session-scoped store, forwards requests to an optional local upstream
OpenAI-compatible server (or produces a local echo response when offline), and
restores ``__BLIND_<KIND>_<SEQ>__`` placeholders in both JSON and SSE streams.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from http import HTTPStatus
import json
import os
import re
import time
from typing import Any, Protocol
from urllib import error as urllib_error
from urllib import request as urllib_request
import uuid

_PREFIX = "__BLIND_"
_COMPLETE_PLACEHOLDER_RE = re.compile(r"__BLIND_[A-Z0-9]+(?:_[A-Z0-9]+)*__")
_INCOMPLETE_PLACEHOLDER_RE = re.compile(r"__BLIND_(?:[A-Z0-9]+(?:_[A-Z0-9]+)*_?)?")
_DEFAULT_MAX_PLACEHOLDER_LEN = 256
_DEFAULT_UPSTREAM_TIMEOUT = 30.0
_DEFAULT_LOCAL_MODEL = "blind-ai-local"


class SessionStoreProtocol(Protocol):
    """Minimal session store interface required by the OpenAI gateway."""

    def sanitize(
        self,
        text: str,
        session_id: str | None = None,
    ) -> tuple[str, str]: ...

    def restore(self, session_id: str, text: str) -> str | None: ...


class GatewayError(Exception):
    """Structured HTTP error raised during gateway request processing."""

    def __init__(self, status: HTTPStatus | int, message: str) -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = message


def _build_mapping_restorer(mapping: Mapping[str, str]) -> Callable[[str], str]:
    """Create a single-pass restore function from a placeholder-to-value mapping."""
    if not mapping:
        return lambda text: text
    ordered = sorted(mapping.keys(), key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(p) for p in ordered))
    snapshot = dict(mapping)
    return lambda text: pattern.sub(lambda match: snapshot[match.group(0)], text)


def _coerce_restorer(
    restorer: Callable[[str], str] | Mapping[str, str] | Any,
) -> Callable[[str], str]:
    """Accept a callable, a vault with ``.restore()``, or a placeholder mapping."""
    if callable(restorer):
        return restorer
    restore_method = getattr(restorer, "restore", None)
    if callable(restore_method):
        return restore_method
    if isinstance(restorer, Mapping):
        return _build_mapping_restorer(restorer)
    raise TypeError(
        "StreamRestorer requires a callable, a vault with .restore(), or a mapping."
    )


class StreamRestorer:
    """Incremental restorer for ``__BLIND_<KIND>_<SEQ>__`` placeholders in text streams.

    Maintains a sliding tail buffer so placeholders split across arbitrary chunk
    boundaries (2, 3, or more chunks) are reassembled and restored before being
    emitted, while non-matching prefixes (e.g. ``__not_blind``) are flushed
    immediately without stalling the stream.
    """

    def __init__(
        self,
        restorer: Callable[[str], str] | Mapping[str, str] | Any,
        *,
        max_placeholder_len: int = _DEFAULT_MAX_PLACEHOLDER_LEN,
    ) -> None:
        self._restore = _coerce_restorer(restorer)
        self._max_placeholder_len = max(len(_PREFIX) + 4, int(max_placeholder_len))
        self._buffer: str = ""

    @property
    def buffered(self) -> str:
        """Return the currently buffered trailing fragment (for diagnostics/tests)."""
        return self._buffer

    def feed(self, chunk: str) -> str:
        """Feed *chunk* into the stream and return the safely restorable prefix."""
        if not chunk:
            return ""

        buf = self._buffer + chunk
        out_parts: list[str] = []
        pos = 0
        buf_len = len(buf)

        while pos < buf_len:
            idx = buf.find("_", pos)
            if idx == -1:
                out_parts.append(buf[pos:])
                pos = buf_len
                break

            if idx > pos:
                out_parts.append(buf[pos:idx])
                pos = idx

            rem = buf[pos:]
            if rem.startswith(_PREFIX):
                match = _COMPLETE_PLACEHOLDER_RE.match(buf, pos)
                if match is not None:
                    out_parts.append(self._restore(match.group(0)))
                    pos = match.end()
                    continue

                if (
                    len(rem) <= self._max_placeholder_len
                    and _INCOMPLETE_PLACEHOLDER_RE.fullmatch(rem) is not None
                ):
                    break

                # False start (e.g., invalid char or oversized token): emit 1 char and continue.
                out_parts.append(buf[pos])
                pos += 1
                continue

            if len(rem) < len(_PREFIX) and _PREFIX.startswith(rem):
                # Partial prefix of "__BLIND_" at the very end of the buffer.
                break

            out_parts.append(buf[pos])
            pos += 1

        self._buffer = buf[pos:]
        return "".join(out_parts)

    def flush(self) -> str:
        """Flush any remaining buffered text at end-of-stream."""
        if not self._buffer:
            return ""
        remaining = self._buffer
        self._buffer = ""
        return self._restore(remaining)


def resolve_upstream_endpoint(upstream_url: str) -> str:
    """Resolve *upstream_url* into a full ``/v1/chat/completions`` URL."""
    base = upstream_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return f"{base}/chat/completions"
    return f"{base}/v1/chat/completions"


def sanitize_chat_request(
    payload: Mapping[str, Any],
    session_store: SessionStoreProtocol,
    *,
    session_id: str | None = None,
) -> tuple[str, dict[str, Any], str]:
    """Validate and sanitize an OpenAI ``/v1/chat/completions`` request payload.

    Returns ``(resolved_session_id, sanitized_payload, last_sanitized_content)``.
    Raises :class:`GatewayError` with HTTP 400 on invalid payloads.
    """
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise GatewayError(
            HTTPStatus.BAD_REQUEST,
            "Field 'messages' is required and must be a non-empty list.",
        )

    model = payload.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip()):
        raise GatewayError(
            HTTPStatus.BAD_REQUEST,
            "Optional field 'model' must be a non-empty string.",
        )

    stream = payload.get("stream", False)
    if not isinstance(stream, bool):
        raise GatewayError(
            HTTPStatus.BAD_REQUEST,
            "Optional field 'stream' must be a boolean.",
        )

    resolved_session_id = session_id
    sanitized_messages: list[dict[str, Any]] = []
    last_user_content: str | None = None
    last_any_content: str = ""

    for idx, msg in enumerate(messages):
        if not isinstance(msg, Mapping):
            raise GatewayError(
                HTTPStatus.BAD_REQUEST,
                f"Message at index {idx} must be a JSON object.",
            )
        role = msg.get("role")
        if not isinstance(role, str) or not role.strip():
            raise GatewayError(
                HTTPStatus.BAD_REQUEST,
                f"Message at index {idx} must have a non-empty string 'role'.",
            )

        msg_copy = dict(msg)
        content = msg.get("content")
        if isinstance(content, str):
            resolved_session_id, sanitized_content = session_store.sanitize(
                content,
                session_id=resolved_session_id,
            )
            msg_copy["content"] = sanitized_content
            last_any_content = sanitized_content
            if role == "user":
                last_user_content = sanitized_content
        elif isinstance(content, list):
            sanitized_parts: list[Any] = []
            collected_text: list[str] = []
            for part in content:
                if isinstance(part, Mapping) and isinstance(part.get("text"), str):
                    part_copy = dict(part)
                    resolved_session_id, sanitized_text = session_store.sanitize(
                        part["text"],
                        session_id=resolved_session_id,
                    )
                    part_copy["text"] = sanitized_text
                    sanitized_parts.append(part_copy)
                    collected_text.append(sanitized_text)
                else:
                    sanitized_parts.append(part)
            msg_copy["content"] = sanitized_parts
            joined = "".join(collected_text)
            if joined:
                last_any_content = joined
                if role == "user":
                    last_user_content = joined
        elif content is not None:
            raise GatewayError(
                HTTPStatus.BAD_REQUEST,
                f"Message at index {idx} 'content' must be a string, list, or null.",
            )

        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            sanitized_tool_calls: list[Any] = []
            for tc in tool_calls:
                if not isinstance(tc, Mapping):
                    sanitized_tool_calls.append(tc)
                    continue
                tc_copy = dict(tc)
                fn = tc_copy.get("function")
                if isinstance(fn, Mapping):
                    fn_copy = dict(fn)
                    args = fn_copy.get("arguments")
                    if isinstance(args, str):
                        resolved_session_id, sanitized_args = session_store.sanitize(
                            args,
                            session_id=resolved_session_id,
                        )
                        fn_copy["arguments"] = sanitized_args
                        if not last_any_content:
                            last_any_content = sanitized_args
                    tc_copy["function"] = fn_copy
                sanitized_tool_calls.append(tc_copy)
            msg_copy["tool_calls"] = sanitized_tool_calls

        sanitized_messages.append(msg_copy)

    if resolved_session_id is None:
        resolved_session_id, _ = session_store.sanitize("", session_id=None)

    outbound = {k: v for k, v in payload.items() if k != "session_id"}
    outbound["messages"] = sanitized_messages
    if "model" not in outbound or outbound["model"] is None:
        outbound["model"] = _DEFAULT_LOCAL_MODEL

    echo_text = last_user_content if last_user_content is not None else last_any_content
    return resolved_session_id, outbound, echo_text


def _restore_for_session(
    session_store: SessionStoreProtocol,
    session_id: str,
    text: str,
    *,
    allowed_placeholders: set[str] | None = None,
) -> str:
    if not text:
        return text
    if allowed_placeholders is not None:
        def _sub(match: re.Match[str]) -> str:
            ph = match.group(0)
            if ph not in allowed_placeholders:
                return ph
            restored_token = session_store.restore(session_id, ph)
            return ph if restored_token is None else restored_token

        return _COMPLETE_PLACEHOLDER_RE.sub(_sub, text)
    restored = session_store.restore(session_id, text)
    return text if restored is None else restored


def _restore_json_response(
    response_body: dict[str, Any],
    session_store: SessionStoreProtocol,
    session_id: str,
    *,
    allowed_placeholders: set[str] | None = None,
) -> dict[str, Any]:
    """Restore placeholders in an OpenAI chat completion JSON object."""
    restored_body = dict(response_body)
    choices = restored_body.get("choices")
    if isinstance(choices, list):
        new_choices: list[Any] = []
        for choice in choices:
            if not isinstance(choice, Mapping):
                new_choices.append(choice)
                continue
            choice_copy = dict(choice)
            message = choice_copy.get("message")
            if isinstance(message, Mapping):
                msg_copy = dict(message)
                if isinstance(msg_copy.get("content"), str):
                    msg_copy["content"] = _restore_for_session(
                        session_store,
                        session_id,
                        msg_copy["content"],
                        allowed_placeholders=allowed_placeholders,
                    )
                tool_calls = msg_copy.get("tool_calls")
                if isinstance(tool_calls, list):
                    restored_tool_calls: list[Any] = []
                    for tc in tool_calls:
                        if not isinstance(tc, Mapping):
                            restored_tool_calls.append(tc)
                            continue
                        tc_copy = dict(tc)
                        fn = tc_copy.get("function")
                        if isinstance(fn, Mapping):
                            fn_copy = dict(fn)
                            if isinstance(fn_copy.get("arguments"), str):
                                fn_copy["arguments"] = _restore_for_session(
                                    session_store,
                                    session_id,
                                    fn_copy["arguments"],
                                    allowed_placeholders=allowed_placeholders,
                                )
                            tc_copy["function"] = fn_copy
                        restored_tool_calls.append(tc_copy)
                    msg_copy["tool_calls"] = restored_tool_calls
                choice_copy["message"] = msg_copy
            if isinstance(choice_copy.get("text"), str):
                choice_copy["text"] = _restore_for_session(
                    session_store,
                    session_id,
                    choice_copy["text"],
                    allowed_placeholders=allowed_placeholders,
                )
            new_choices.append(choice_copy)
        restored_body["choices"] = new_choices
    return restored_body


def _build_local_echo_json(
    model: str,
    sanitized_text: str,
    session_store: SessionStoreProtocol,
    session_id: str,
) -> dict[str, Any]:
    """Construct an OpenAI-formatted local echo completion JSON response."""
    restored_text = _restore_for_session(session_store, session_id, sanitized_text)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": restored_text,
                },
                "finish_reason": "stop",
            }
        ],
    }


def _iter_local_echo_sse(
    model: str,
    sanitized_text: str,
    session_store: SessionStoreProtocol,
    session_id: str,
    *,
    chunk_size: int = 7,
) -> Iterator[bytes]:
    """Generate an OpenAI-formatted SSE stream locally via :class:`StreamRestorer`."""
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created = int(time.time())
    restorer = StreamRestorer(
        lambda text: _restore_for_session(session_store, session_id, text)
    )

    first = True
    step = max(1, chunk_size)
    for start in range(0, len(sanitized_text), step):
        piece = restorer.feed(sanitized_text[start : start + step])
        if piece:
            delta: dict[str, Any] = {"content": piece}
            if first:
                delta["role"] = "assistant"
                first = False
            event = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": delta,
                        "finish_reason": None,
                    }
                ],
            }
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")

    flushed = restorer.flush()
    if flushed or first:
        delta = {"content": flushed}
        if first:
            delta["role"] = "assistant"
        event = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")

    stop_event = {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }
        ],
    }
    yield f"data: {json.dumps(stop_event, ensure_ascii=False)}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


def _resolve_upstream_api_key(upstream_api_key: str | None) -> str | None:
    if upstream_api_key is not None and upstream_api_key.strip():
        return upstream_api_key.strip()
    env_key = os.environ.get("BLIND_AI_UPSTREAM_API_KEY")
    if env_key is not None and env_key.strip():
        return env_key.strip()
    return None


def _forward_json_upstream(
    upstream_url: str,
    outbound_payload: Mapping[str, Any],
    session_store: SessionStoreProtocol,
    session_id: str,
    *,
    upstream_api_key: str | None = None,
    timeout: float = _DEFAULT_UPSTREAM_TIMEOUT,
    allowed_placeholders: set[str] | None = None,
) -> dict[str, Any]:
    endpoint = resolve_upstream_endpoint(upstream_url)
    body_bytes = json.dumps(outbound_payload, ensure_ascii=False).encode("utf-8")
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    resolved_key = _resolve_upstream_api_key(upstream_api_key)
    if resolved_key:
        headers["Authorization"] = f"Bearer {resolved_key}"
    req = urllib_request.Request(
        endpoint,
        data=body_bytes,
        headers=headers,
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib_error.HTTPError as exc:
        raise GatewayError(
            HTTPStatus.BAD_GATEWAY,
            f"Upstream returned HTTP {exc.code}.",
        ) from exc
    except (urllib_error.URLError, TimeoutError, OSError) as exc:
        raise GatewayError(
            HTTPStatus.BAD_GATEWAY,
            f"Failed to reach upstream server: {exc}",
        ) from exc

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayError(
            HTTPStatus.BAD_GATEWAY,
            "Upstream returned invalid UTF-8 JSON.",
        ) from exc

    if not isinstance(parsed, dict):
        raise GatewayError(
            HTTPStatus.BAD_GATEWAY,
            "Upstream JSON response must be an object.",
        )

    return _restore_json_response(
        parsed,
        session_store,
        session_id,
        allowed_placeholders=allowed_placeholders,
    )


def _iter_upstream_sse(
    upstream_url: str,
    outbound_payload: Mapping[str, Any],
    session_store: SessionStoreProtocol,
    session_id: str,
    *,
    upstream_api_key: str | None = None,
    timeout: float = _DEFAULT_UPSTREAM_TIMEOUT,
    allowed_placeholders: set[str] | None = None,
) -> Iterator[bytes]:
    endpoint = resolve_upstream_endpoint(upstream_url)
    body_bytes = json.dumps(outbound_payload, ensure_ascii=False).encode("utf-8")
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    resolved_key = _resolve_upstream_api_key(upstream_api_key)
    if resolved_key:
        headers["Authorization"] = f"Bearer {resolved_key}"
    req = urllib_request.Request(
        endpoint,
        data=body_bytes,
        headers=headers,
        method="POST",
    )
    try:
        resp = urllib_request.urlopen(req, timeout=timeout)
    except urllib_error.HTTPError as exc:
        raise GatewayError(
            HTTPStatus.BAD_GATEWAY,
            f"Upstream returned HTTP {exc.code}.",
        ) from exc
    except (urllib_error.URLError, TimeoutError, OSError) as exc:
        raise GatewayError(
            HTTPStatus.BAD_GATEWAY,
            f"Failed to reach upstream server: {exc}",
        ) from exc

    def _stream() -> Iterator[bytes]:
        restorers: dict[int, StreamRestorer] = {}
        tool_restorers: dict[tuple[int, int], StreamRestorer] = {}
        last_meta: dict[str, Any] = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": str(outbound_payload.get("model") or _DEFAULT_LOCAL_MODEL),
        }

        def _get_restorer(choice_idx: int) -> StreamRestorer:
            restorer = restorers.get(choice_idx)
            if restorer is None:
                restorer = StreamRestorer(
                    lambda text: _restore_for_session(
                        session_store,
                        session_id,
                        text,
                        allowed_placeholders=allowed_placeholders,
                    )
                )
                restorers[choice_idx] = restorer
            return restorer

        def _get_tool_restorer(choice_idx: int, tc_idx: int) -> StreamRestorer:
            key = (choice_idx, tc_idx)
            restorer = tool_restorers.get(key)
            if restorer is None:
                restorer = StreamRestorer(
                    lambda text: _restore_for_session(
                        session_store,
                        session_id,
                        text,
                        allowed_placeholders=allowed_placeholders,
                    )
                )
                tool_restorers[key] = restorer
            return restorer

        def _flush_choice_events(choice_idx: int) -> Iterator[bytes]:
            if choice_idx in restorers:
                flushed = restorers[choice_idx].flush()
                if flushed:
                    event = {
                        **last_meta,
                        "choices": [
                            {
                                "index": choice_idx,
                                "delta": {"content": flushed},
                                "finish_reason": None,
                            }
                        ],
                    }
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")

            tc_keys = sorted(k for k in tool_restorers if k[0] == choice_idx)
            flushed_tcs: list[dict[str, Any]] = []
            for _, tc_idx in tc_keys:
                flushed_arg = tool_restorers[(choice_idx, tc_idx)].flush()
                if flushed_arg:
                    flushed_tcs.append(
                        {
                            "index": tc_idx,
                            "function": {"arguments": flushed_arg},
                        }
                    )
            if flushed_tcs:
                event = {
                    **last_meta,
                    "choices": [
                        {
                            "index": choice_idx,
                            "delta": {"tool_calls": flushed_tcs},
                            "finish_reason": None,
                        }
                    ],
                }
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")

        def _flush_events() -> Iterator[bytes]:
            all_choices = sorted(
                set(restorers.keys()) | {choice_idx for choice_idx, _ in tool_restorers}
            )
            for choice_idx in all_choices:
                yield from _flush_choice_events(choice_idx)

        done_emitted = False
        try:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line or line.startswith(":"):
                    continue
                if not line.startswith("data:"):
                    continue

                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    yield from _flush_events()
                    yield b"data: [DONE]\n\n"
                    done_emitted = True
                    break

                try:
                    chunk_obj = json.loads(data_str)
                except json.JSONDecodeError:
                    continue

                if not isinstance(chunk_obj, dict):
                    continue

                for key in ("id", "object", "created", "model"):
                    if key in chunk_obj:
                        last_meta[key] = chunk_obj[key]

                choices = chunk_obj.get("choices")
                pre_flush_events: list[bytes] = []
                if isinstance(choices, list):
                    for choice in choices:
                        if not isinstance(choice, dict):
                            continue
                        choice_idx = int(choice.get("index", 0))
                        delta = choice.get("delta")
                        if isinstance(delta, dict):
                            if isinstance(delta.get("content"), str):
                                restorer = _get_restorer(choice_idx)
                                delta["content"] = restorer.feed(delta["content"])
                            tool_calls = delta.get("tool_calls")
                            if isinstance(tool_calls, list):
                                for pos_idx, tc in enumerate(tool_calls):
                                    if not isinstance(tc, dict):
                                        continue
                                    tc_idx = int(tc.get("index", pos_idx))
                                    fn = tc.get("function")
                                    if isinstance(fn, dict) and isinstance(
                                        fn.get("arguments"), str
                                    ):
                                        tc_restorer = _get_tool_restorer(choice_idx, tc_idx)
                                        fn["arguments"] = tc_restorer.feed(fn["arguments"])
                        if choice.get("finish_reason") is not None:
                            pre_flush_events.extend(_flush_choice_events(choice_idx))

                for pre_event in pre_flush_events:
                    yield pre_event
                yield f"data: {json.dumps(chunk_obj, ensure_ascii=False)}\n\n".encode("utf-8")

            if not done_emitted:
                yield from _flush_events()
                yield b"data: [DONE]\n\n"
        finally:
            resp.close()

    return _stream()


def handle_chat_completions(
    payload: Mapping[str, Any],
    session_store: SessionStoreProtocol,
    *,
    session_id: str | None = None,
    upstream_url: str | None = None,
    upstream_api_key: str | None = None,
    timeout: float = _DEFAULT_UPSTREAM_TIMEOUT,
) -> tuple[str, bool, dict[str, Any] | Iterator[bytes]]:
    """Process a ``POST /v1/chat/completions`` request.

    Returns ``(resolved_session_id, is_stream, result)`` where ``result`` is a
    JSON-serializable ``dict`` when ``is_stream`` is ``False`` or an iterator of
    UTF-8 SSE event byte chunks when ``is_stream`` is ``True``.
    """
    resolved_session_id, outbound, echo_text = sanitize_chat_request(
        payload,
        session_store,
        session_id=session_id,
    )
    request_placeholders = set(
        _COMPLETE_PLACEHOLDER_RE.findall(
            json.dumps(outbound.get("messages", []), ensure_ascii=False)
        )
    )
    is_stream = bool(outbound.get("stream", False))
    model = str(outbound.get("model") or _DEFAULT_LOCAL_MODEL)

    if is_stream:
        if upstream_url:
            stream_iter = _iter_upstream_sse(
                upstream_url,
                outbound,
                session_store,
                resolved_session_id,
                upstream_api_key=upstream_api_key,
                timeout=timeout,
                allowed_placeholders=request_placeholders,
            )
        else:
            stream_iter = _iter_local_echo_sse(
                model,
                echo_text,
                session_store,
                resolved_session_id,
            )
        return resolved_session_id, True, stream_iter

    if upstream_url:
        json_body = _forward_json_upstream(
            upstream_url,
            outbound,
            session_store,
            resolved_session_id,
            upstream_api_key=upstream_api_key,
            timeout=timeout,
            allowed_placeholders=request_placeholders,
        )
    else:
        json_body = _build_local_echo_json(
            model,
            echo_text,
            session_store,
            resolved_session_id,
        )
    return resolved_session_id, False, json_body
