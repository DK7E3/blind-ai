"""Unit tests for the Blind-AI synthetic benchmark and metrics evaluator."""

from pathlib import Path
import sys
import unittest

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from blind_ai.core.benchmark import (  # noqa: E402
    BenchmarkCase,
    BenchmarkMetrics,
    build_synthetic_dataset,
    evaluate_detector,
)


class TestSyntheticDataset(unittest.TestCase):
    def test_dataset_covers_all_three_categories(self) -> None:
        dataset = build_synthetic_dataset()
        self.assertGreater(len(dataset), 0)

        categories = {case.category for case in dataset}
        self.assertEqual(categories, {"structured", "contextual", "clean"})

        structured = [c for c in dataset if c.category == "structured"]
        contextual = [c for c in dataset if c.category == "contextual"]
        clean = [c for c in dataset if c.category == "clean"]

        self.assertGreaterEqual(len(structured), 6)
        self.assertGreaterEqual(len(contextual), 2)
        self.assertGreaterEqual(len(clean), 2)

    def test_dataset_case_fields_and_consistency(self) -> None:
        dataset = build_synthetic_dataset()
        case_ids = [case.case_id for case in dataset]
        self.assertEqual(len(case_ids), len(set(case_ids)))

        for case in dataset:
            self.assertIsInstance(case, BenchmarkCase)
            self.assertIsInstance(case.expected_kinds, tuple)
            if case.category == "clean":
                self.assertFalse(case.expected_sensitive)
                self.assertEqual(case.expected_kinds, ())
            else:
                self.assertTrue(case.expected_sensitive)
                self.assertGreater(len(case.expected_kinds), 0)

    def test_structured_cases_cover_fictitious_patterns(self) -> None:
        dataset = build_synthetic_dataset()
        structured_texts = [c.text for c in dataset if c.category == "structured"]

        self.assertTrue(any("AKIA" in text for text in structured_texts))
        self.assertTrue(any("sk-" in text for text in structured_texts))
        self.assertTrue(any("ghp_" in text for text in structured_texts))
        self.assertTrue(any("eyJ" in text for text in structured_texts))
        self.assertTrue(
            any("/internal/" in text or "\\internal\\" in text for text in structured_texts)
        )
        self.assertTrue(
            any("10." in text or "192.168." in text for text in structured_texts)
        )

    def test_invalid_category_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            BenchmarkCase(
                case_id="invalid-01",
                text="sample",
                expected_sensitive=False,
                category="unknown",
            )


class TestEvaluateDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.dataset = build_synthetic_dataset()
        self.expected_by_text = {
            case.text: case.expected_sensitive for case in self.dataset
        }
        self.total_positives = sum(1 for c in self.dataset if c.expected_sensitive)
        self.total_negatives = sum(1 for c in self.dataset if not c.expected_sensitive)

    def test_oracle_detector_bool_output(self) -> None:
        def oracle(text: str) -> bool:
            return self.expected_by_text[text]

        metrics = evaluate_detector(oracle)
        self.assertIsInstance(metrics, BenchmarkMetrics)
        self.assertEqual(metrics.tp, self.total_positives)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, 0)
        self.assertEqual(metrics.tn, self.total_negatives)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertGreaterEqual(metrics.avg_latency_ms, 0.0)

    def test_oracle_detector_sequence_output(self) -> None:
        def sequence_oracle(text: str) -> list[dict[str, str]]:
            if self.expected_by_text[text]:
                return [{"kind": "secret"}]
            return []

        metrics = evaluate_detector(sequence_oracle, self.dataset)
        self.assertEqual(metrics.tp, self.total_positives)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, 0)
        self.assertEqual(metrics.tn, self.total_negatives)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertGreaterEqual(metrics.avg_latency_ms, 0.0)

    def test_all_negative_detector_handles_zero_division(self) -> None:
        metrics = evaluate_detector(lambda _text: False, self.dataset)
        self.assertEqual(metrics.tp, 0)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, self.total_positives)
        self.assertEqual(metrics.tn, self.total_negatives)
        self.assertEqual(metrics.recall, 0.0)
        self.assertEqual(metrics.precision, 0.0)
        self.assertGreaterEqual(metrics.avg_latency_ms, 0.0)

    def test_mixed_cases_exact_metrics(self) -> None:
        custom_cases = [
            BenchmarkCase("p1", "secret-1", True, "structured", ("aws_access_key",)),
            BenchmarkCase("p2", "secret-2", True, "structured", ("jwt",)),
            BenchmarkCase("p3", "secret-3", True, "contextual", ("sensitive_comment",)),
            BenchmarkCase("n1", "clean-1", False, "clean"),
            BenchmarkCase("n2", "clean-2", False, "clean"),
        ]
        # Predicts True for p1, p2 (2 TP), n1 (1 FP); False for p3 (1 FN), n2 (1 TN)
        flagged = {"secret-1", "secret-2", "clean-1"}

        def mixed_detector(text: str) -> tuple[str, ...]:
            return (text,) if text in flagged else ()

        metrics = evaluate_detector(mixed_detector, custom_cases)
        self.assertEqual(metrics.tp, 2)
        self.assertEqual(metrics.fp, 1)
        self.assertEqual(metrics.fn, 1)
        self.assertEqual(metrics.tn, 1)
        self.assertAlmostEqual(metrics.recall, 2 / 3)
        self.assertAlmostEqual(metrics.precision, 2 / 3)
        self.assertGreaterEqual(metrics.avg_latency_ms, 0.0)

    def test_empty_dataset_returns_zeroed_metrics(self) -> None:
        metrics = evaluate_detector(lambda _text: True, [])
        self.assertEqual(metrics.tp, 0)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, 0)
        self.assertEqual(metrics.tn, 0)
        self.assertEqual(metrics.recall, 0.0)
        self.assertEqual(metrics.precision, 0.0)
        self.assertEqual(metrics.avg_latency_ms, 0.0)


if __name__ == "__main__":
    unittest.main()
