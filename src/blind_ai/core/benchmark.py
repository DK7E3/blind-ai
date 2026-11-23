"""Synthetic benchmark dataset and evaluation metrics for Blind-AI detectors.

Uses only the Python 3.12 standard library. All benchmark cases are 100%
fictitious and cover structured secrets, contextual secrets, and clean code.
"""

from dataclasses import dataclass
import time
from typing import Callable, Sequence

VALID_CATEGORIES = frozenset({"structured", "contextual", "clean"})


@dataclass(frozen=True)
class BenchmarkCase:
    """A single synthetic benchmark case."""

    case_id: str
    text: str
    expected_sensitive: bool
    category: str
    expected_kinds: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category {self.category!r}. "
                f"Expected one of {sorted(VALID_CATEGORIES)}."
            )


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Confusion-matrix metrics and average latency for a detector evaluation."""

    tp: int
    fp: int
    fn: int
    tn: int
    recall: float
    precision: float
    avg_latency_ms: float


def build_synthetic_dataset() -> list[BenchmarkCase]:
    """Build a 100% fictitious dataset with structured, contextual, and clean cases."""
    return [
        # --- Structured positive cases ---
        BenchmarkCase(
            case_id="struct-aws-01",
            text=(
                "AWS_ACCESS_KEY_ID=AKIAFAKE0000EXAMPLE1\n"
                "AWS_DEFAULT_REGION=us-east-1\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("aws_access_key",),
        ),
        BenchmarkCase(
            case_id="struct-openai-02",
            text=(
                "client_config = {\n"
                '    "provider": "openai",\n'
                '    "api_key": "sk-proj-fake0000example1111token2222abcd3333efgh4444",\n'
                "}\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("openai_api_key",),
        ),
        BenchmarkCase(
            case_id="struct-github-03",
            text=(
                "GITHUB_TOKEN=ghp_FakeExampleToken00001111222233334444\n"
                "REPO_NAME=example-org/sample-service\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("github_token",),
        ),
        BenchmarkCase(
            case_id="struct-jwt-04",
            text=(
                "Authorization: Bearer "
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiJmYWtlLXVzZXItMDAxIiwicm9sZSI6InRlc3QifQ."
                "fakeSignaturePayload0000111122223333\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("jwt",),
        ),
        BenchmarkCase(
            case_id="struct-internal-path-05",
            text=(
                "CERT_PATH=/srv/internal/acme-fictional/secrets/prod-billing.pem\n"
                "BACKUP_DIR=C:\\internal\\corp-vault\\staging\\ledger.key\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("internal_path",),
        ),
        BenchmarkCase(
            case_id="struct-private-ip-06",
            text=(
                "upstream_primary = '10.24.108.42'\n"
                "upstream_replica = '192.168.144.27'\n"
            ),
            expected_sensitive=True,
            category="structured",
            expected_kinds=("private_ip",),
        ),
        # --- Contextual positive cases ---
        BenchmarkCase(
            case_id="ctx-comment-pass-01",
            text=(
                "# Temporary staging database password for weekend migration:\n"
                "# WinterFictionalPass!2026\n"
                "def connect_staging() -> None:\n"
                "    pass\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        BenchmarkCase(
            case_id="ctx-comment-runbook-02",
            text=(
                "# Emergency vault override passphrase for fictional cluster:\n"
                "# orange-river-falcon-99 (rotate immediately after drill)\n"
                "DRILL_ENABLED = True\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        BenchmarkCase(
            case_id="ctx-comment-webhook-03",
            text=(
                "// Shared finance webhook signing secret (sandbox only):\n"
                "// use whsec_fictional_finance_0192 for local tests\n"
                "const webhookEnabled = true;\n"
            ),
            expected_sensitive=True,
            category="contextual",
            expected_kinds=("sensitive_comment",),
        ),
        # --- Clean negative cases ---
        BenchmarkCase(
            case_id="clean-math-01",
            text=(
                "def calculate_average(values: list[float]) -> float:\n"
                "    if not values:\n"
                "        return 0.0\n"
                "    return sum(values) / len(values)\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        BenchmarkCase(
            case_id="clean-http-status-02",
            text=(
                "HTTP_STATUS_LABELS = {\n"
                '    200: "OK",\n'
                '    404: "Not Found",\n'
                '    503: "Service Unavailable",\n'
                "}\n"
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
        BenchmarkCase(
            case_id="clean-docs-03",
            text=(
                '"""Formatter helpers for public release notes."""\n\n'
                "def slugify_title(title: str) -> str:\n"
                '    return "-".join(title.lower().split())\n'
            ),
            expected_sensitive=False,
            category="clean",
            expected_kinds=(),
        ),
    ]


def _to_prediction(result: bool | Sequence[object]) -> bool:
    """Convert a detector output (bool or finding sequence) into a boolean."""
    if isinstance(result, bool):
        return result
    return len(result) > 0


def evaluate_detector(
    detector: Callable[[str], bool | Sequence[object]],
    dataset: Sequence[BenchmarkCase] | None = None,
) -> BenchmarkMetrics:
    """Evaluate a detector on the benchmark dataset and return aggregate metrics."""
    cases = list(dataset) if dataset is not None else build_synthetic_dataset()
    if not cases:
        return BenchmarkMetrics(
            tp=0,
            fp=0,
            fn=0,
            tn=0,
            recall=0.0,
            precision=0.0,
            avg_latency_ms=0.0,
        )

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    total_latency_ms = 0.0

    for case in cases:
        start_ms = time.perf_counter() * 1000.0
        raw_result = detector(case.text)
        elapsed_ms = (time.perf_counter() * 1000.0) - start_ms
        total_latency_ms += elapsed_ms

        predicted_sensitive = _to_prediction(raw_result)
        if case.expected_sensitive and predicted_sensitive:
            tp += 1
        elif not case.expected_sensitive and predicted_sensitive:
            fp += 1
        elif case.expected_sensitive and not predicted_sensitive:
            fn += 1
        else:
            tn += 1

    recall_denom = tp + fn
    precision_denom = tp + fp
    recall = tp / recall_denom if recall_denom > 0 else 0.0
    precision = tp / precision_denom if precision_denom > 0 else 0.0
    avg_latency_ms = total_latency_ms / len(cases)

    return BenchmarkMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        recall=recall,
        precision=precision,
        avg_latency_ms=avg_latency_ms,
    )
