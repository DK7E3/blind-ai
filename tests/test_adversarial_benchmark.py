"""Unit tests for the multi-language adversarial benchmark (stdlib only)."""

from __future__ import annotations

import re
import unittest

from blind_ai.core.adversarial_benchmark import (
    VALID_LANGUAGES,
    AdversarialCase,
    AdversarialMetrics,
    build_adversarial_dataset,
    run_adversarial_benchmark,
)
from blind_ai.core.benchmark import BenchmarkCase
from blind_ai.core.contextual import HybridScanner

_UUID_V4_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_GIT_SHA1_RE = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)


class _AlwaysPositiveScanner:
    """Stub scanner that always flags text as sensitive."""

    def scan_text(self, text: str) -> list[str]:
        return ["stub_finding"] if text else []


class TestAdversarialDataset(unittest.TestCase):
    def test_dataset_minimum_size_and_uniqueness(self) -> None:
        dataset = build_adversarial_dataset()
        self.assertGreaterEqual(len(dataset), 15)

        ids = [case.case_id for case in dataset]
        self.assertEqual(len(ids), len(set(ids)))

        for case in dataset:
            self.assertIsInstance(case, AdversarialCase)
            self.assertIsInstance(case, BenchmarkCase)
            self.assertIn(case.language, VALID_LANGUAGES)

    def test_multilanguage_coverage(self) -> None:
        dataset = build_adversarial_dataset()
        languages = {case.language for case in dataset}
        expected_languages = {
            "python",
            "javascript",
            "typescript",
            "yaml",
            "json",
            "sql",
            "logs",
        }
        self.assertTrue(expected_languages.issubset(languages))

    def test_categories_and_benign_uuid_sha_presence(self) -> None:
        dataset = build_adversarial_dataset()
        structured = [c for c in dataset if c.category == "structured"]
        contextual = [c for c in dataset if c.category == "contextual"]
        clean = [c for c in dataset if c.category == "clean"]

        self.assertGreater(len(structured), 0)
        self.assertGreater(len(contextual), 0)
        self.assertGreater(len(clean), 0)

        self.assertTrue(all(c.expected_sensitive for c in structured))
        self.assertTrue(all(c.expected_sensitive for c in contextual))
        self.assertTrue(all(not c.expected_sensitive for c in clean))

        self.assertTrue(any(_UUID_V4_RE.search(c.text) for c in clean))
        self.assertTrue(any(_GIT_SHA1_RE.search(c.text) for c in clean))
        self.assertTrue(any(_SHA256_RE.search(c.text) for c in clean))

    def test_invalid_language_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            AdversarialCase(
                case_id="invalid-lang",
                text="print('hi')",
                expected_sensitive=False,
                category="clean",
                language="cobol",
            )


class TestRunAdversarialBenchmark(unittest.TestCase):
    def test_hybrid_scanner_metrics_and_zero_fp_on_benign_tokens(self) -> None:
        dataset = build_adversarial_dataset()
        metrics = run_adversarial_benchmark(dataset=dataset, scanner=HybridScanner())

        self.assertIsInstance(metrics, AdversarialMetrics)
        self.assertEqual(metrics.total_cases, len(dataset))
        self.assertEqual(
            metrics.tp + metrics.fp + metrics.fn + metrics.tn,
            metrics.total_cases,
        )
        self.assertGreaterEqual(metrics.recall, 0.0)
        self.assertLessEqual(metrics.recall, 1.0)
        self.assertGreaterEqual(metrics.precision, 0.0)
        self.assertLessEqual(metrics.precision, 1.0)
        self.assertGreaterEqual(metrics.fpr, 0.0)
        self.assertLessEqual(metrics.fpr, 1.0)
        self.assertGreaterEqual(metrics.avg_latency_ms, 0.0)

        # Benign UUIDv4 and Git SHA-1/SHA-256 cases must not trigger false positives.
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fpr, 0.0)
        self.assertGreater(metrics.tp, 0)
        self.assertGreater(metrics.tn, 0)
        self.assertEqual(metrics.fn, 0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.precision, 1.0)

    def test_default_arguments_use_hybrid_scanner_and_full_dataset(self) -> None:
        metrics = run_adversarial_benchmark()
        self.assertGreaterEqual(metrics.total_cases, 15)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fpr, 0.0)

    def test_empty_dataset_returns_zeroed_metrics(self) -> None:
        metrics = run_adversarial_benchmark(dataset=[])
        self.assertEqual(metrics.total_cases, 0)
        self.assertEqual(metrics.tp, 0)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, 0)
        self.assertEqual(metrics.tn, 0)
        self.assertEqual(metrics.recall, 0.0)
        self.assertEqual(metrics.precision, 0.0)
        self.assertEqual(metrics.fpr, 0.0)
        self.assertEqual(metrics.avg_latency_ms, 0.0)

    def test_fpr_computation_with_always_positive_scanner(self) -> None:
        dataset = build_adversarial_dataset()
        metrics = run_adversarial_benchmark(
            dataset=dataset,
            scanner=_AlwaysPositiveScanner(),
        )
        expected_negatives = sum(1 for c in dataset if not c.expected_sensitive)
        self.assertEqual(metrics.fp, expected_negatives)
        self.assertEqual(metrics.tn, 0)
        self.assertEqual(metrics.fpr, 1.0)


if __name__ == "__main__":
    unittest.main()
