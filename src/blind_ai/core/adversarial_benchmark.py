"""Multi-language adversarial benchmark for Blind-AI detectors.

Uses only the Python 3.12 standard library. All benchmark cases are 100%
fictitious and span Python, JavaScript, TypeScript, YAML, JSON, SQL, and logs,
covering structured secrets, contextual leaks, and benign high-entropy tokens
such as UUIDv4 identifiers and Git SHA-1/SHA-256 hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from blind_ai.core.benchmark import BenchmarkCase, evaluate_detector
from blind_ai.core.contextual import HybridScanner

VALID_LANGUAGES: frozenset[str] = frozenset(
    {"python", "javascript", "typescript", "yaml", "json", "sql", "logs"}
)


class _TextScanner(Protocol):
    """Protocol for any scanner exposing ``scan_text(text)``."""

    def scan_text(self, text: str) -> Sequence[object]: ...


@dataclass(frozen=True)
class AdversarialCase(BenchmarkCase):
    """A multi-language adversarial benchmark case compatible with BenchmarkCase."""

    language: str = "python"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.language not in VALID_LANGUAGES:
            raise ValueError(
                f"Invalid language {self.language!r}. "
                f"Expected one of {sorted(VALID_LANGUAGES)}."
            )


@dataclass(frozen=True)
class AdversarialMetrics:
    """Aggregate confusion-matrix metrics, FPR, case count, and average latency."""

    tp: int
    fp: int
    fn: int
    tn: int
    recall: float
    precision: float
    fpr: float
    avg_latency_ms: float
    total_cases: int


def build_adversarial_dataset() -> list[AdversarialCase]:
    """Build a 100% fictitious multi-language adversarial dataset (>= 15 cases)."""
    return [
        # --- Structured positive cases ---
        AdversarialCase(
            case_id="adv-py-aws-01",
            language="python",
            text=(
                "STORAGE_CONFIG = {\n"
                '    "region": "us-east-1",\n'
                '    "access_key_id": "AKIAFAKE0000BENCH001",\n'
                "}\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("aws_access_key",),
        ),
        AdversarialCase(
            case_id="adv-js-openai-02",
            language="javascript",
            text=(
                "export const aiClientConfig = {\n"
                '  provider: "openai",\n'
                '  apiKey: "sk-proj-fake0000bench1111js2222abcd3333efgh4444",\n'
                "};\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("openai_api_key",),
        ),
        AdversarialCase(
            case_id="adv-ts-github-03",
            language="typescript",
            text=(
                "interface RepoAuth {\n"
                "  readonly token: string;\n"
                "}\n"
                "export const repoAuth: RepoAuth = {\n"
                '  token: "ghp_FakeTsBenchToken00001111222233334444",\n'
                "};\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("github_token",),
        ),
        AdversarialCase(
            case_id="adv-json-jwt-04",
            language="json",
            text=(
                "{\n"
                '  "service": "billing-sandbox",\n'
                '  "authorization": "Bearer '
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiJmYWtlLWpzb24tMDAxIiwicm9sZSI6InRlc3QifQ."
                'fakeSignaturePayload0000111122223333"\n'
                "}\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("jwt",),
        ),
        AdversarialCase(
            case_id="adv-yaml-infra-05",
            language="yaml",
            text=(
                "service:\n"
                "  name: ledger-sync\n"
                "  tls_cert: /srv/internal/acme-fictional/secrets/billing.pem\n"
                "  upstream_host: 10.42.88.19\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("internal_path", "private_ip"),
        ),
        AdversarialCase(
            case_id="adv-sql-aws-06",
            language="sql",
            text=(
                "INSERT INTO fictional_sync_targets (host_ip, access_key)\n"
                "VALUES ('10.88.12.5', 'AKIAFAKE7777SQLEX003');\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("private_ip", "aws_access_key"),
        ),
        AdversarialCase(
            case_id="adv-logs-aws-07",
            language="logs",
            text=(
                "2026-11-22T09:12:04Z ERROR uploader: failed auth against "
                "192.168.50.12 using key AKIAFAKE9999LOGEX002\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("private_ip", "aws_access_key"),
        ),
        # --- Contextual positive cases ---
        AdversarialCase(
            case_id="adv-py-ctx-comment-08",
            language="python",
            text=(
                "# Temporary staging database password for cutover:\n"
                "# AutumnFictionalPass!2026\n"
                "def open_staging_pool() -> None:\n"
                "    pass\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        AdversarialCase(
            case_id="adv-js-ctx-comment-09",
            language="javascript",
            text=(
                "// Sandbox finance webhook signing secret:\n"
                "// use whsec_fictional_js_hook_0421 for local replay\n"
                "export const replayEnabled = true;\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        AdversarialCase(
            case_id="adv-ts-ctx-block-10",
            language="typescript",
            text=(
                "/* Emergency vault override passphrase for drill:\n"
                " * cobalt-cedar-falcon-77\n"
                " */\n"
                "export const drillMode: boolean = true;\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        AdversarialCase(
            case_id="adv-yaml-ctx-pass-11",
            language="yaml",
            text=(
                "database:\n"
                "  # Temporary migration password for fictional staging DB:\n"
                "  # WinterFictionalPass!2026\n"
                "  pool_size: 8\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        AdversarialCase(
            case_id="adv-sql-ctx-comment-12",
            language="sql",
            text=(
                "/* Temporary database password for weekend migration:\n"
                " * GlacierFictionalPwd!2026\n"
                " */\n"
                "SELECT count(*) FROM fictional_accounts;\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        AdversarialCase(
            case_id="adv-logs-ctx-inline-13",
            language="logs",
            text=(
                "2026-11-22T10:00:00Z WARN auth: temporary admin password is "
                "CopperFictionalKey!2026\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        # --- Benign negative cases (UUIDv4, Git SHA-1/SHA-256, clean code) ---
        AdversarialCase(
            case_id="adv-py-clean-uuid-14",
            language="python",
            text=(
                'DEFAULT_REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"\n\n'
                "def format_trace_header(request_id: str) -> str:\n"
                '    return f"X-Request-Id: {request_id}"\n'
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        AdversarialCase(
            case_id="adv-js-clean-sha1-15",
            language="javascript",
            text=(
                'const commitSha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4";\n'
                "export function shortCommit(sha) {\n"
                "  return sha.slice(0, 7);\n"
                "}\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        AdversarialCase(
            case_id="adv-ts-clean-sha256-16",
            language="typescript",
            text=(
                "export interface ArtifactDigest {\n"
                "  readonly sha256: string;\n"
                "}\n"
                "export const releaseDigest: ArtifactDigest = {\n"
                '  sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",\n'
                "};\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        AdversarialCase(
            case_id="adv-yaml-clean-uuid-sha-17",
            language="yaml",
            text=(
                "release:\n"
                "  correlation_id: f47ac10b-58cc-4372-a567-0e02b2c3d479\n"
                "  git_commit: 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
                "  replicas: 3\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        AdversarialCase(
            case_id="adv-json-clean-uuid-sha256-18",
            language="json",
            text=(
                "{\n"
                '  "trace_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",\n'
                '  "checksum_sha256": '
                '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",\n'
                '  "status": "ok"\n'
                "}\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        AdversarialCase(
            case_id="adv-sql-clean-uuid-sha1-19",
            language="sql",
            text=(
                "SELECT release_id, commit_hash\n"
                "FROM public_releases\n"
                "WHERE release_uuid = '123e4567-e89b-12d3-a456-426614174000'\n"
                "  AND commit_hash = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        AdversarialCase(
            case_id="adv-logs-clean-uuid-sha1-20",
            language="logs",
            text=(
                "2026-11-22T10:15:00Z INFO http: "
                "request_id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 "
                "commit=2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 "
                "status=200 latency_ms=14\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
    ]


def run_adversarial_benchmark(
    dataset: Sequence[BenchmarkCase] | None = None,
    scanner: _TextScanner | None = None,
) -> AdversarialMetrics:
    """Run the adversarial benchmark with HybridScanner and return AdversarialMetrics."""
    cases = list(dataset) if dataset is not None else build_adversarial_dataset()
    active_scanner = scanner if scanner is not None else HybridScanner()

    base = evaluate_detector(active_scanner.scan_text, cases)
    fpr_denom = base.fp + base.tn
    fpr = base.fp / fpr_denom if fpr_denom > 0 else 0.0
    total_cases = base.tp + base.fp + base.fn + base.tn

    return AdversarialMetrics(
        tp=base.tp,
        fp=base.fp,
        fn=base.fn,
        tn=base.tn,
        recall=base.recall,
        precision=base.precision,
        fpr=fpr,
        avg_latency_ms=base.avg_latency_ms,
        total_cases=total_cases,
    )
