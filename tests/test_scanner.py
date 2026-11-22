"""Unit tests and H1 benchmark validation for Layer 2 DeterministicScanner."""

from dataclasses import FrozenInstanceError
import unittest

from blind_ai.core.benchmark import build_synthetic_dataset, evaluate_detector
from blind_ai.core.scanner import DeterministicScanner, Finding, shannon_entropy


class TestShannonEntropyAndFinding(unittest.TestCase):
    """Tests for shannon_entropy helper and Finding dataclass invariants."""

    def test_shannon_entropy_values(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaaaaaaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0, places=6)
        self.assertGreaterEqual(shannon_entropy("Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6"), 3.8)

    def test_finding_is_frozen_and_slotted(self) -> None:
        finding = Finding(
            kind="aws_access_key",
            value="AKIAFAKE0000EXAMPLE1",
            start=0,
            end=20,
            line=1,
            source="regex",
            confidence=0.98,
        )
        self.assertTrue(hasattr(Finding, "__slots__"))
        with self.assertRaises(FrozenInstanceError):
            finding.kind = "other"  # type: ignore[misc]


class TestDeterministicScannerDetections(unittest.TestCase):
    """Tests covering all 7 finding types, AST fallback, deduplication, and clean code."""

    def setUp(self) -> None:
        self.scanner = DeterministicScanner()

    def test_detects_aws_access_key(self) -> None:
        text = "AWS_ACCESS_KEY_ID=AKIAFAKE0000EXAMPLE1\n"
        findings = self.scanner.scan_text(text)
        kinds = [f.kind for f in findings]
        self.assertEqual(kinds, ["aws_access_key"])
        self.assertEqual(findings[0].value, "AKIAFAKE0000EXAMPLE1")
        self.assertEqual(findings[0].line, 1)
        self.assertEqual(findings[0].source, "regex")

    def test_detects_openai_api_key_and_deduplicates_ast_overlap(self) -> None:
        text = (
            'OPENAI_KEY = "sk-proj-fake0000example1111token2222abcd3333efgh4444"\n'
            'LEGACY_KEY = "sk-fake0000example1111token2222abcd"\n'
        )
        findings = self.scanner.scan_text(text)
        self.assertEqual([f.kind for f in findings], ["openai_api_key", "openai_api_key"])
        self.assertEqual(findings[0].line, 1)
        self.assertEqual(findings[1].line, 2)

    def test_detects_github_tokens(self) -> None:
        text = (
            "TOKEN_A=ghp_FakeExampleToken00001111222233334444\n"
            "TOKEN_B=github_pat_11FAKE00001111222233334444_abcdEFGH\n"
        )
        findings = self.scanner.scan_text(text)
        self.assertEqual([f.kind for f in findings], ["github_token", "github_token"])

    def test_detects_jwt(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJmYWtlLXVzZXItMDAxIiwicm9sZSI6InRlc3QifQ."
            "fakeSignaturePayload0000111122223333"
        )
        findings = self.scanner.scan_text(f"Authorization: Bearer {token}\n")
        self.assertEqual([f.kind for f in findings], ["jwt"])
        self.assertEqual(findings[0].value, token)

    def test_detects_private_ip_and_ignores_public_or_invalid_ips(self) -> None:
        text = (
            "primary = '10.24.108.42'\n"
            "secondary = '172.16.5.10'\n"
            "lan = '192.168.144.27'\n"
            "public_dns = '8.8.8.8'\n"
            "invalid_ip = '999.999.1.1'\n"
        )
        findings = self.scanner.scan_text(text)
        self.assertEqual(
            [(f.kind, f.value) for f in findings],
            [
                ("private_ip", "10.24.108.42"),
                ("private_ip", "172.16.5.10"),
                ("private_ip", "192.168.144.27"),
            ],
        )

    def test_detects_internal_paths_and_ignores_urls(self) -> None:
        text = (
            "CERT_PATH=/srv/internal/acme-fictional/secrets/prod-billing.pem\n"
            "BACKUP_DIR=C:\\internal\\corp-vault\\staging\\ledger.key\n"
            "DOCS_URL=https://example.com/srv/internal/docs/guide\n"
        )
        findings = self.scanner.scan_text(text)
        self.assertEqual([f.kind for f in findings], ["internal_path", "internal_path"])
        self.assertEqual(
            findings[0].value,
            "/srv/internal/acme-fictional/secrets/prod-billing.pem",
        )
        self.assertEqual(
            findings[1].value,
            "C:\\internal\\corp-vault\\staging\\ledger.key",
        )

    def test_detects_high_entropy_token_via_ast(self) -> None:
        text = (
            '"""Module docstring with long_non_secret_word_for_testing_purposes."""\n'
            'SERVICE_SECRET = "Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6"\n'
            'NORMAL_IDENTIFIER = "calculate_monthly_revenue_summary"\n'
        )
        findings = self.scanner.scan_text(text)
        self.assertEqual([f.kind for f in findings], ["high_entropy_token"])
        self.assertEqual(findings[0].value, "Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6")
        self.assertEqual(findings[0].source, "ast_entropy")
        self.assertEqual(findings[0].line, 2)

    def test_non_python_syntax_error_falls_back_silently(self) -> None:
        non_python_text = (
            "server {\n"
            "    proxy_pass http://10.10.0.15:8080;\n"
            "    # aws key: AKIAFAKE0000EXAMPLE9\n"
            "}\n"
        )
        findings = self.scanner.scan_text(non_python_text)
        kinds = {f.kind for f in findings}
        self.assertIn("private_ip", kinds)
        self.assertIn("aws_access_key", kinds)

    def test_clean_code_produces_zero_findings(self) -> None:
        clean_samples = [
            "",
            (
                '"""Public utility module for arithmetic."""\n'
                "def average(nums: list[float]) -> float:\n"
                "    return sum(nums) / len(nums) if nums else 0.0\n"
            ),
            (
                'DOCS = "https://docs.example.org/api/v1/reference"\n'
                'PUBLIC_DNS = "1.1.1.1"\n'
                'STATUS_TEXT = "Service Unavailable"\n'
            ),
        ]
        for sample in clean_samples:
            with self.subTest(sample=sample[:30]):
                self.assertEqual(self.scanner.scan_text(sample), [])


class TestHypothesisH1Benchmark(unittest.TestCase):
    """Validates Hypothesis H1 on the synthetic benchmark dataset."""

    def setUp(self) -> None:
        self.scanner = DeterministicScanner()
        self.dataset = build_synthetic_dataset()

    def test_h1_structured_recall_and_latency(self) -> None:
        structured_cases = [c for c in self.dataset if c.category == "structured"]
        self.assertTrue(structured_cases)

        metrics = evaluate_detector(self.scanner.scan_text, structured_cases)
        self.assertGreaterEqual(
            metrics.recall,
            0.95,
            f"H1 failed: structured recall={metrics.recall:.4f} < 0.95",
        )
        self.assertLess(
            metrics.avg_latency_ms,
            100.0,
            f"H1 failed: avg_latency_ms={metrics.avg_latency_ms:.2f} >= 100.0",
        )

        for case in structured_cases:
            detected_kinds = {f.kind for f in self.scanner.scan_text(case.text)}
            for expected_kind in case.expected_kinds:
                self.assertIn(
                    expected_kind,
                    detected_kinds,
                    f"Case {case.case_id} missing expected kind {expected_kind!r}",
                )

    def test_clean_cases_zero_false_positives(self) -> None:
        clean_cases = [c for c in self.dataset if c.category == "clean"]
        self.assertTrue(clean_cases)

        metrics = evaluate_detector(self.scanner.scan_text, clean_cases)
        self.assertEqual(
            metrics.fp,
            0,
            f"Expected 0 false positives on clean cases, got {metrics.fp}",
        )


if __name__ == "__main__":
    unittest.main()
