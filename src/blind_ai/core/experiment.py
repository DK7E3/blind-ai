"""Scientific H1 vs H2 experiment comparing deterministic and hybrid scanning.

Uses only the Python 3.12 standard library and 100% synthetic benchmark data:
- H1: DeterministicScanner (Regex + Shannon entropy + Python AST)
- H2: HybridScanner (DeterministicScanner + ContextualDetector)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Sequence

from blind_ai.core.benchmark import (
    BenchmarkCase,
    BenchmarkMetrics,
    build_synthetic_dataset,
    evaluate_detector,
)
from blind_ai.core.contextual import ContextualDetector, HybridScanner
from blind_ai.core.scanner import DeterministicScanner

__all__ = [
    "ExperimentReport",
    "HybridScanner",
    "run_h1_vs_h2_experiment",
]


@dataclass(frozen=True, slots=True)
class ExperimentReport:
    """Objective comparative report for H1 (Deterministic) vs H2 (Hybrid)."""

    h1_name: str
    h2_name: str
    dataset_size: int
    h1_metrics: BenchmarkMetrics
    h2_metrics: BenchmarkMetrics
    recall_delta: float
    precision_delta: float
    latency_delta_ms: float

    def to_dict(self) -> dict[str, object]:
        """Serialize the experiment report into a plain dictionary."""
        return {
            "dataset_size": self.dataset_size,
            "h1": {
                "name": self.h1_name,
                "metrics": asdict(self.h1_metrics),
            },
            "h2": {
                "name": self.h2_name,
                "metrics": asdict(self.h2_metrics),
            },
            "deltas": {
                "recall_delta": self.recall_delta,
                "precision_delta": self.precision_delta,
                "latency_delta_ms": self.latency_delta_ms,
            },
        }

    def format_summary(self) -> str:
        """Render a concise, objective comparison summary (Recall, Precision, Latency)."""
        lines = [
            f"Blind-AI H1 vs H2 Synthetic Experiment (n={self.dataset_size} cases)",
            "-" * 72,
            f"{'Detector':<36} {'Recall':>8} {'Precision':>10} {'Latency(ms)':>12}",
            "-" * 72,
            (
                f"{self.h1_name:<36} "
                f"{self.h1_metrics.recall:>8.4f} "
                f"{self.h1_metrics.precision:>10.4f} "
                f"{self.h1_metrics.avg_latency_ms:>12.4f}"
            ),
            (
                f"{self.h2_name:<36} "
                f"{self.h2_metrics.recall:>8.4f} "
                f"{self.h2_metrics.precision:>10.4f} "
                f"{self.h2_metrics.avg_latency_ms:>12.4f}"
            ),
            "-" * 72,
            (
                f"{'Delta (H2 - H1)':<36} "
                f"{self.recall_delta:>+8.4f} "
                f"{self.precision_delta:>+10.4f} "
                f"{self.latency_delta_ms:>+12.4f}"
            ),
            (
                f"H1 Confusion: TP={self.h1_metrics.tp} FP={self.h1_metrics.fp} "
                f"FN={self.h1_metrics.fn} TN={self.h1_metrics.tn}"
            ),
            (
                f"H2 Confusion: TP={self.h2_metrics.tp} FP={self.h2_metrics.fp} "
                f"FN={self.h2_metrics.fn} TN={self.h2_metrics.tn}"
            ),
        ]
        return "\n".join(lines)


def run_h1_vs_h2_experiment(
    dataset: Sequence[BenchmarkCase] | None = None,
    *,
    deterministic_scanner: DeterministicScanner | None = None,
    hybrid_scanner: HybridScanner | None = None,
) -> ExperimentReport:
    """Run the H1 vs H2 experiment on synthetic benchmark cases."""
    cases = list(dataset) if dataset is not None else build_synthetic_dataset()

    h1_scanner = deterministic_scanner or DeterministicScanner()
    h2_scanner = hybrid_scanner or HybridScanner(
        deterministic=DeterministicScanner(),
        contextual=ContextualDetector(),
    )

    h1_metrics = evaluate_detector(h1_scanner.scan_text, cases)
    h2_metrics = evaluate_detector(h2_scanner.scan_text, cases)

    return ExperimentReport(
        h1_name="H1: DeterministicScanner",
        h2_name="H2: HybridScanner",
        dataset_size=len(cases),
        h1_metrics=h1_metrics,
        h2_metrics=h2_metrics,
        recall_delta=h2_metrics.recall - h1_metrics.recall,
        precision_delta=h2_metrics.precision - h1_metrics.precision,
        latency_delta_ms=h2_metrics.avg_latency_ms - h1_metrics.avg_latency_ms,
    )
