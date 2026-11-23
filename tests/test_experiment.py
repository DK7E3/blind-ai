"""Unit tests for Layer 3 contextual detection and the H1 vs H2 experiment."""

from __future__ import annotations

import unittest

from blind_ai.core.benchmark import BenchmarkCase, build_synthetic_dataset
from blind_ai.core.contextual import ContextualDetector, HybridScanner
from blind_ai.core.experiment import ExperimentReport, run_h1_vs_h2_experiment
from blind_ai.core.scanner import DeterministicScanner, Finding


class TestContextualDetector(unittest.TestCase):
    """Tests for ContextualDetector on comments, free text, and clean code."""

    def setUp(self) -> None:
        self.deterministic = DeterministicScanner()
        self.contextual = ContextualDetector()
        self.dataset = build_synthetic_dataset()

    def test_detects_benchmark_contextual_cases_missed_by_deterministic(self) -> None:
        contextual_cases = [c for c in self.dataset if c.category == "contextual"]
        self.assertGreaterEqual(len(contextual_cases), 3)

        for case in contextual_cases:
            with self.subTest(case_id=case.case_id):
                det_findings = self.deterministic.scan_text(case.text)
                self.assertEqual(
                    det_findings,
                    [],
                    f"Expected DeterministicScanner to miss {case.case_id}",
                )

                ctx_findings = self.contextual.scan_text(case.text)
                self.assertGreaterEqual(
                    len(ctx_findings),
                    1,
                    f"Expected ContextualDetector to flag {case.case_id}",
                )
                for finding in ctx_findings:
                    self.assertIsInstance(finding, Finding)
                    self.assertEqual(finding.kind, "sensitive_comment")
                    self.assertEqual(finding.source, "contextual")
                    self.assertEqual(case.text[finding.start : finding.end], finding.value)
                    self.assertGreaterEqual(finding.line, 1)

    def test_detects_block_comments_and_free_text_leaks(self) -> None:
        samples = [
            (
                "block_comment",
                (
                    "/* Temporary internal secret for staging drill:\n"
                    " * amber-cedar-falcon-42\n"
                    " */\n"
                    "const ok = true;\n"
                ),
                "amber-cedar-falcon-42",
            ),
            (
                "inline_double_slash",
                "// sandbox webhook signing secret: whsec_demo_ledger_8841\n",
                "whsec_demo_ledger_8841",
            ),
            (
                "free_text_prose",
                (
                    "Runbook note for local QA:\n"
                    "Staging password is AutumnVault#2026 for the mock database.\n"
                ),
                "AutumnVault#2026",
            ),
        ]

        for label, text, expected_value in samples:
            with self.subTest(sample=label):
                self.assertEqual(self.deterministic.scan_text(text), [])
                findings = self.contextual.scan_text(text)
                self.assertTrue(
                    any(f.value == expected_value for f in findings),
                    f"Expected {expected_value!r} in {[f.value for f in findings]}",
                )
                for finding in findings:
                    self.assertEqual(finding.kind, "sensitive_comment")
                    self.assertEqual(finding.source, "contextual")
                    self.assertEqual(text[finding.start : finding.end], finding.value)

    def test_zero_false_positives_on_clean_benchmark_cases(self) -> None:
        clean_cases = [c for c in self.dataset if c.category == "clean"]
        self.assertGreaterEqual(len(clean_cases), 3)

        for case in clean_cases:
            with self.subTest(case_id=case.case_id):
                self.assertEqual(self.contextual.scan_text(case.text), [])

    def test_zero_false_positives_on_benign_security_comments_and_placeholders(self) -> None:
        benign_samples = [
            "# Validate user password length before storing the hash.\n",
            "// Rotate webhook secret every 90 days according to policy.\n",
            "/* Internal helper returns True when token expiration is valid. */\n",
            "# password: <redacted>\n# token: CHANGEME\n# secret: your-secret-here\n",
            (
                "def check_password(user_password: str) -> bool:\n"
                "    # Check Python 3.12 compatibility (updated 2026-11-22, HTTP/1.1)\n"
                "    return len(user_password) >= 12\n"
            ),
        ]

        for idx, text in enumerate(benign_samples):
            with self.subTest(sample_index=idx):
                self.assertEqual(self.contextual.scan_text(text), [])

    def test_rejects_comment_code_expressions_and_underscore_bounded_cues(self) -> None:
        self.assertEqual(ContextualDetector._score_secret_candidate("token[0][:0"), 0.0)
        self.assertEqual(ContextualDetector._score_secret_candidate("self._userinfo[1"), 0.0)
        self.assertEqual(ContextualDetector._score_secret_candidate("secure=None"), 0.0)
        self.assertEqual(ContextualDetector._score_secret_candidate("parse_XXX"), 0.0)

        # Line 1 has '_secret_helper' (underscore boundary must prevent cue trigger on line 1);
        # Line 4 has an explicit 'password' cue with code expressions that must be rejected.
        comment_with_code_and_underscore_id = (
            "# Uses _secret_helper with candidate Zx9Kp2Lm4Nq7Rs1Tv8\n\n\n"
            "# password note: token[0][:0] self._userinfo[1] secure=None parse_XXX\n"
        )
        self.assertEqual(self.contextual.scan_text(comment_with_code_and_underscore_id), [])


class TestHybridScanner(unittest.TestCase):
    """Tests for HybridScanner combining Layer 2 and Layer 3 with deduplication."""

    def test_hybrid_detects_both_structured_and_contextual_without_overlaps(self) -> None:
        scanner = HybridScanner()
        text = (
            "# Temporary staging password:\n"
            "# WinterFictionalPass!2026\n"
            "AWS_ACCESS_KEY_ID=AKIAFAKE0000EXAMPLE1\n"
            "# Repeat key in comment: AKIAFAKE0000EXAMPLE1\n"
        )
        findings = scanner.scan_text(text)

        kinds = {f.kind for f in findings}
        self.assertIn("aws_access_key", kinds)
        self.assertIn("sensitive_comment", kinds)

        # Verify spans are strictly non-overlapping and sorted.
        for prev, curr in zip(findings, findings[1:]):
            self.assertLessEqual(prev.end, curr.start)


class TestH1VsH2Experiment(unittest.TestCase):
    """Tests for the scientific H1 vs H2 comparison report."""

    def test_h1_vs_h2_experiment_improves_recall_and_preserves_precision(self) -> None:
        report = run_h1_vs_h2_experiment()
        self.assertIsInstance(report, ExperimentReport)

        self.assertEqual(report.dataset_size, len(build_synthetic_dataset()))
        self.assertGreater(report.h2_metrics.recall, report.h1_metrics.recall)
        self.assertGreater(report.recall_delta, 0.0)

        self.assertEqual(report.h1_metrics.fp, 0)
        self.assertEqual(report.h2_metrics.fp, 0)
        self.assertEqual(report.h1_metrics.precision, 1.0)
        self.assertEqual(report.h2_metrics.precision, 1.0)
        self.assertEqual(report.precision_delta, 0.0)
        self.assertEqual(report.h2_metrics.recall, 1.0)

        self.assertGreaterEqual(report.h1_metrics.avg_latency_ms, 0.0)
        self.assertGreaterEqual(report.h2_metrics.avg_latency_ms, 0.0)

        payload = report.to_dict()
        self.assertEqual(payload["dataset_size"], report.dataset_size)
        self.assertIn("h1", payload)
        self.assertIn("h2", payload)
        self.assertIn("deltas", payload)

        summary = report.format_summary()
        self.assertIn("H1", summary)
        self.assertIn("H2", summary)
        self.assertIn("Recall", summary)
        self.assertIn("Precision", summary)
        self.assertIn("Latency", summary)
        self.assertIn("Delta", summary)

    def test_experiment_accepts_custom_synthetic_dataset(self) -> None:
        custom_cases = [
            BenchmarkCase(
                case_id="custom-ctx-01",
                text="// Internal migration passphrase: cedar-river-comet-77\n",
                expected_sensitive=True,
                category="contextual",
                expected_kinds=("sensitive_comment",),
            ),
            BenchmarkCase(
                case_id="custom-clean-01",
                text="# Helper to sum numbers cleanly.\ndef add(a: int, b: int) -> int:\n    return a + b\n",
                expected_sensitive=False,
                category="clean",
            ),
        ]
        report = run_h1_vs_h2_experiment(dataset=custom_cases)
        self.assertEqual(report.dataset_size, 2)
        self.assertEqual(report.h1_metrics.recall, 0.0)
        self.assertEqual(report.h2_metrics.recall, 1.0)
        self.assertEqual(report.h2_metrics.precision, 1.0)
        self.assertEqual(report.h2_metrics.fp, 0)


if __name__ == "__main__":
    unittest.main()
