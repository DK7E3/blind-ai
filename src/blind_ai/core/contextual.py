"""Experimental Layer 3 contextual detector and HybridScanner.

Uses only the Python 3.12 standard library. Detects contextual secret leaks
in comments (#, //, /* */) and free text / prose that purely regex/AST
scanners miss, while avoiding false positives on clean code and benign docs.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from blind_ai.core.scanner import (
    DeterministicScanner,
    Finding,
    _line_number,
    _spans_overlap,
    shannon_entropy,
)

_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")
_DATE_RE = re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}$")
_SEMVER_RE = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9.]+)?$")
_PROTOCOL_RE = re.compile(r"^[A-Z]{2,8}/?\d+(?:\.\d+)?$")

# Strong credential/secret context cues (matched as whole words, case-insensitive).
_STRONG_CUE_RE = re.compile(
    r"\b(?:"
    r"passwords?|passwds?|passphrases?|pwd|"
    r"secrets?|tokens?|apikeys?|api[_ -]?keys?|"
    r"webhooks?|credentials?|creds?|"
    r"vault|override|bearer|private[_ -]?keys?|signing"
    r")\b",
    re.IGNORECASE,
)

# Secondary context modifiers that reinforce sensitivity when paired with a
# secret-like candidate entity.
_CONTEXT_MODIFIER_RE = re.compile(
    r"\b(?:"
    r"internal|staging|sandbox|prod|production|"
    r"temporary|temp|emergency|migration|shared|"
    r"finance|database|db|admin|root|runbook|drill|backup"
    r")\b",
    re.IGNORECASE,
)

# Known prefixes for structured secret tokens often pasted into comments/notes.
_SECRET_PREFIX_RE = re.compile(
    r"^(?:whsec|sec|tok|token|key|pwd|pass|pat|api|sk|rk|pk|auth|cred)_[A-Za-z0-9_-]{6,}$",
    re.IGNORECASE,
)

# Hyphenated passphrase: 3+ segments, with at least one digit OR 4+ word segments.
_PASSPHRASE_RE = re.compile(r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+){2,}$")

# Token extractor preserving exact character offsets inside a line.
_TOKEN_RE = re.compile(r"\S+")

# Block comment pattern (/* ... */).
_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")

# Single-line comment patterns (# ... and // ... avoiding URLs like https://).
_LINE_COMMENT_RE = re.compile(r"(?:(?<!\w)#.*$|(?<![:/])//.*$)")

# Linking words/separators used when scanning non-comment free text.
_FREE_TEXT_ASSIGN_RE = re.compile(
    r"(?:"
    r"\b(?:passwords?|passwds?|passphrases?|pwd|secrets?|tokens?|webhooks?|credentials?|api[_ -]?keys?)\b"
    r"\s*(?:[:=]|->|=>|\bis\b|\bare\b|\buse\b)\s*"
    r")",
    re.IGNORECASE,
)

_PLACEHOLDER_WORDS: frozenset[str] = frozenset(
    {
        "changeme",
        "redacted",
        "placeholder",
        "todo",
        "fixme",
        "none",
        "null",
        "true",
        "false",
        "undefined",
        "your-password-here",
        "your_password_here",
        "your-secret-here",
        "your_secret_here",
        "your-token-here",
        "your_token_here",
        "not-a-secret",
        "read-only-mode",
    }
)

_EDGE_PUNCT = "()[]{}<>\"'`,;:.!?"


@dataclass(frozen=True, slots=True)
class _LineSlice:
    """A slice of a single line with its exact offset in the original text."""

    line_no: int
    start: int
    end: int
    content: str
    is_comment: bool


def _strip_edge_punctuation(raw_token: str, raw_start: int) -> tuple[str, int, int]:
    """Strip wrapper punctuation while preserving exact character offsets."""
    left = 0
    right = len(raw_token)

    while left < right and raw_token[left] in _EDGE_PUNCT:
        left += 1
    while right > left and raw_token[right - 1] in _EDGE_PUNCT:
        # Preserve trailing '!' or '?' only if it is embedded, not wrapper.
        right -= 1

    return raw_token[left:right], raw_start + left, raw_start + right


def _is_placeholder(token: str) -> bool:
    lowered = token.lower()
    if lowered in _PLACEHOLDER_WORDS:
        return True
    if lowered.startswith(("your_", "your-", "example_", "example-", "sample_")):
        return True
    if token.startswith("<") and token.endswith(">"):
        return True
    return False


def _score_secret_candidate(token: str) -> float:
    """Return a heuristic score in [0.0, 1.0] for whether *token* looks like a secret.

    Returns 0.0 for ordinary English words, code identifiers, dates, versions,
    URLs, and placeholders.
    """
    if len(token) < 8:
        return 0.0
    if _URL_RE.match(token) or _DATE_RE.match(token) or _SEMVER_RE.match(token):
        return 0.0
    if _PROTOCOL_RE.match(token) or _is_placeholder(token):
        return 0.0
    # Reject obvious code call expressions or dotted attribute chains without digits.
    if "(" in token or ")" in token:
        return 0.0
    if "." in token and not any(ch.isdigit() for ch in token):
        return 0.0

    # 1. Prefixed structured secret (e.g., whsec_fictional_finance_0192).
    if _SECRET_PREFIX_RE.match(token):
        return 0.90

    # 2. Snake-case secret with digits (e.g., finance_sandbox_key_0192) — excludes
    #    pure alphabetic identifiers like `validate_user_password` or `WEBHOOK_SECRET`.
    if "_" in token and any(ch.isdigit() for ch in token) and len(token) >= 12:
        parts = [p for p in token.split("_") if p]
        if len(parts) >= 2 and any(ch.isalpha() for ch in token):
            return 0.84

    # 3. Hyphenated passphrase (e.g., orange-river-falcon-99).
    if _PASSPHRASE_RE.match(token) and len(token) >= 12:
        parts = token.split("-")
        has_digit = any(ch.isdigit() for ch in token)
        if len(parts) >= 3 and (has_digit or len(parts) >= 4):
            return 0.86

    has_lower = any(ch.islower() for ch in token)
    has_upper = any(ch.isupper() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    has_symbol = any(not ch.isalnum() for ch in token)
    class_count = int(has_lower) + int(has_upper) + int(has_digit) + int(has_symbol)

    # 4. Mixed-class password/token (e.g., WinterFictionalPass!2026).
    if class_count >= 3 and len(token) >= 8:
        return 0.88

    # 5. Alphanumeric high-entropy token (letters + digits, length >= 12).
    if has_digit and (has_lower or has_upper) and len(token) >= 12:
        if shannon_entropy(token) >= 3.2:
            return 0.82

    return 0.0


def _extract_comment_slices(text: str) -> tuple[list[_LineSlice], list[tuple[int, int]]]:
    """Extract comment line slices (#, //, /* */) and their covered spans."""
    slices: list[_LineSlice] = []
    covered_spans: list[tuple[int, int]] = []

    # First capture /* ... */ block comments.
    for block_match in _BLOCK_COMMENT_RE.finditer(text):
        b_start, b_end = block_match.span()
        covered_spans.append((b_start, b_end))
        block_text = block_match.group(0)
        offset = b_start
        for raw_line in block_text.splitlines(keepends=True):
            line_body = raw_line.rstrip("\r\n")
            cleaned = line_body
            # Strip leading /*, trailing */, and leading * markers while tracking offset.
            lead_trim = 0
            if cleaned.startswith("/*"):
                lead_trim = 2
                cleaned = cleaned[2:]
            stripped_lead = cleaned.lstrip(" \t*")
            lead_trim += len(cleaned) - len(stripped_lead)
            cleaned = stripped_lead
            if cleaned.endswith("*/"):
                cleaned = cleaned[:-2]
            if cleaned.strip():
                slices.append(
                    _LineSlice(
                        line_no=_line_number(text, offset),
                        start=offset + lead_trim,
                        end=offset + lead_trim + len(cleaned),
                        content=cleaned,
                        is_comment=True,
                    )
                )
            offset += len(raw_line)

    # Then capture # and // line comments outside block comments.
    offset = 0
    for line_no, raw_line in enumerate(text.splitlines(keepends=True), start=1):
        line_body = raw_line.rstrip("\r\n")
        match = _LINE_COMMENT_RE.search(line_body)
        if match is not None:
            c_start = offset + match.start()
            c_end = offset + match.end()
            if not any(_spans_overlap(c_start, c_end, b_s, b_e) for b_s, b_e in covered_spans):
                covered_spans.append((c_start, c_end))
                marker_len = 2 if match.group(0).startswith("//") else 1
                inner = match.group(0)[marker_len:]
                slices.append(
                    _LineSlice(
                        line_no=line_no,
                        start=c_start + marker_len,
                        end=c_end,
                        content=inner,
                        is_comment=True,
                    )
                )
        offset += len(raw_line)

    slices.sort(key=lambda s: (s.line_no, s.start))
    return slices, covered_spans


def _group_adjacent_slices(slices: list[_LineSlice], max_line_gap: int = 1) -> list[list[_LineSlice]]:
    """Group comment slices on consecutive lines into contextual blocks."""
    if not slices:
        return []
    groups: list[list[_LineSlice]] = [[slices[0]]]
    for current in slices[1:]:
        if current.line_no - groups[-1][-1].line_no <= max_line_gap:
            groups[-1].append(current)
        else:
            groups.append([current])
    return groups


class ContextualDetector:
    """Layer 3 experimental contextual detector for comments and free text.

    Uses local cue matching (password, passphrase, secret, token, webhook,
    internal, etc.) combined with a sliding line/token window and local NER
    heuristics to flag contextual secret leaks that pure regex/AST rules miss.
    """

    def __init__(
        self,
        *,
        line_window: int = 2,
        min_confidence: float = 0.78,
    ) -> None:
        self.line_window = max(0, line_window)
        self.min_confidence = min_confidence

    def scan_text(self, text: str) -> list[Finding]:
        """Scan *text* for contextual leaks in comments and free text."""
        if not text:
            return []

        comment_slices, comment_spans = _extract_comment_slices(text)
        findings: list[Finding] = []
        findings.extend(self._scan_comment_blocks(text, comment_slices))
        findings.extend(self._scan_free_text(text, comment_spans))
        return _deduplicate_findings(findings)

    def _scan_comment_blocks(
        self,
        text: str,
        comment_slices: list[_LineSlice],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for group in _group_adjacent_slices(comment_slices, max_line_gap=1):
            # Track the most recent line with a strong cue or modifier inside the block.
            cue_lines: dict[int, tuple[bool, bool]] = {}
            for item in group:
                has_strong = bool(_STRONG_CUE_RE.search(item.content))
                has_modifier = bool(_CONTEXT_MODIFIER_RE.search(item.content))
                if has_strong or has_modifier:
                    cue_lines[item.line_no] = (has_strong, has_modifier)

            if not cue_lines:
                continue

            for item in group:
                active_strong = False
                active_modifier = False
                for cue_line, (is_strong, is_mod) in cue_lines.items():
                    if 0 <= item.line_no - cue_line <= self.line_window:
                        active_strong = active_strong or is_strong
                        active_modifier = active_modifier or is_mod

                if not active_strong:
                    continue

                for tok_match in _TOKEN_RE.finditer(item.content):
                    token, abs_start, abs_end = _strip_edge_punctuation(
                        tok_match.group(0), item.start + tok_match.start()
                    )
                    if not token:
                        continue
                    score = _score_secret_candidate(token)
                    if score <= 0.0:
                        continue

                    confidence = min(0.92, score + (0.02 if active_modifier else 0.0))
                    if confidence < self.min_confidence:
                        continue

                    findings.append(
                        Finding(
                            kind="sensitive_comment",
                            value=token,
                            start=abs_start,
                            end=abs_end,
                            line=_line_number(text, abs_start),
                            source="contextual",
                            confidence=round(confidence, 2),
                        )
                    )
        return findings

    def _scan_free_text(
        self,
        text: str,
        comment_spans: list[tuple[int, int]],
    ) -> list[Finding]:
        """Scan non-comment lines for explicit contextual leaks in prose/strings."""
        findings: list[Finding] = []
        lines = text.splitlines(keepends=True)
        offsets: list[int] = []
        running = 0
        for raw_line in lines:
            offsets.append(running)
            running += len(raw_line)

        for idx, raw_line in enumerate(lines):
            line_start = offsets[idx]
            line_body = raw_line.rstrip("\r\n")
            line_end = line_start + len(line_body)

            # Skip lines fully covered by comments.
            if any(c_s <= line_start and c_end >= line_end for c_s, c_end in comment_spans):
                continue

            # Pattern A: inline cue + separator (e.g., "password: WinterFictionalPass!2026")
            for assign_match in _FREE_TEXT_ASSIGN_RE.finditer(line_body):
                tail_start = assign_match.end()
                tail = line_body[tail_start:]
                # Inspect up to the next 3 tokens after the cue separator.
                for tok_idx, tok_match in enumerate(_TOKEN_RE.finditer(tail)):
                    if tok_idx >= 3:
                        break
                    abs_raw_start = line_start + tail_start + tok_match.start()
                    token, abs_start, abs_end = _strip_edge_punctuation(
                        tok_match.group(0), abs_raw_start
                    )
                    if not token:
                        continue
                    if any(
                        _spans_overlap(abs_start, abs_end, c_s, c_end)
                        for c_s, c_end in comment_spans
                    ):
                        continue

                    score = _score_secret_candidate(token)
                    if score <= 0.0:
                        continue

                    confidence = round(min(0.90, score), 2)
                    if confidence < self.min_confidence:
                        continue

                    findings.append(
                        Finding(
                            kind="sensitive_comment",
                            value=token,
                            start=abs_start,
                            end=abs_end,
                            line=_line_number(text, abs_start),
                            source="contextual",
                            confidence=confidence,
                        )
                    )
                    break

            # Pattern B: cue line ending with ":" followed by a secret on the next line.
            if (
                line_body.rstrip().endswith(":")
                and _STRONG_CUE_RE.search(line_body)
                and idx + 1 < len(lines)
            ):
                next_start = offsets[idx + 1]
                next_body = lines[idx + 1].rstrip("\r\n")
                for tok_match in _TOKEN_RE.finditer(next_body):
                    abs_raw_start = next_start + tok_match.start()
                    token, abs_start, abs_end = _strip_edge_punctuation(
                        tok_match.group(0), abs_raw_start
                    )
                    if not token:
                        continue
                    if any(
                        _spans_overlap(abs_start, abs_end, c_s, c_end)
                        for c_s, c_end in comment_spans
                    ):
                        continue
                    score = _score_secret_candidate(token)
                    if score <= 0.0:
                        continue
                    confidence = round(min(0.90, score), 2)
                    if confidence < self.min_confidence:
                        continue
                    findings.append(
                        Finding(
                            kind="sensitive_comment",
                            value=token,
                            start=abs_start,
                            end=abs_end,
                            line=_line_number(text, abs_start),
                            source="contextual",
                            confidence=confidence,
                        )
                    )

        return findings


def _deduplicate_findings(candidates: Iterable[Finding]) -> list[Finding]:
    """Deduplicate overlapping findings, preferring higher confidence and longer spans."""
    ranked = sorted(
        candidates,
        key=lambda f: (-f.confidence, -(f.end - f.start), f.start, f.kind),
    )
    accepted: list[Finding] = []
    for candidate in ranked:
        if any(
            _spans_overlap(candidate.start, candidate.end, kept.start, kept.end)
            for kept in accepted
        ):
            continue
        accepted.append(candidate)

    accepted.sort(key=lambda f: (f.start, f.end, f.kind))
    return accepted


class HybridScanner:
    """Combines DeterministicScanner (Layer 2) with ContextualDetector (Layer 3)."""

    def __init__(
        self,
        *,
        deterministic: DeterministicScanner | None = None,
        contextual: ContextualDetector | None = None,
    ) -> None:
        self.deterministic = deterministic or DeterministicScanner()
        self.contextual = contextual or ContextualDetector()

    def scan_text(self, text: str) -> list[Finding]:
        """Scan *text* using both deterministic and contextual layers with deduplication."""
        if not text:
            return []

        combined: list[Finding] = []
        combined.extend(self.deterministic.scan_text(text))
        combined.extend(self.contextual.scan_text(text))
        return _deduplicate_findings(combined)
