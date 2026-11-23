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
            "loopback = '127.0.0.1'\n"
            "unspecified = '0.0.0.0'\n"
            "version_like = '0.5.1.2'\n"
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

    def test_detects_url_credentials_in_postgres_and_https(self) -> None:
        text = (
            'DB_URL = "postgres://admin:SuperS3cret!@db.internal:5432/prod"\n'
            'API_URL = "https://user:p4ssw0rd@host/api"\n'
            'PUBLIC_URL = "https://docs.example.org/v1/guide"\n'
        )
        findings = self.scanner.scan_text(text)
        self.assertEqual(
            [(f.kind, f.value, f.line) for f in findings],
            [
                ("url_credentials", "SuperS3cret!", 1),
                ("url_credentials", "p4ssw0rd", 2),
            ],
        )

    def test_detects_pem_stripe_slack_google_anthropic_and_bearer(self) -> None:
        stripe_sk = "_".join(("sk", "live", "51FakeStripeSecret000011112222"))
        stripe_rk = "_".join(("rk", "live", "51FakeRestricted000011112222"))
        slack_bot = "-".join(("xoxb", "123456789012", "1234567890123", "FakeSlackBotToken99"))
        slack_user = "-".join(("xoxp", "123456789012", "1234567890123", "FakeSlackUserToken88"))
        google_key = "AIza" + "SyFakeGoogleApiKey00001111222233334"
        anthropic_key = "-".join(("sk", "ant", "api03", "FakeAnthropicKey0000111122223333"))
        pem_hdr = "-----BEGIN " + "RSA PRIVATE KEY-----"
        pem_ftr = "-----END " + "RSA PRIVATE KEY-----"
        text = (
            f"{pem_hdr}\n"
            "MIIEpAIBAAKCAQEA0fakeKeyMaterial0000111122223333\n"
            f"{pem_ftr}\n"
            f"STRIPE_SECRET={stripe_sk}\n"
            f"STRIPE_RESTRICTED={stripe_rk}\n"
            f"SLACK_BOT={slack_bot}\n"
            f"SLACK_USER={slack_user}\n"
            f"GOOGLE_KEY={google_key}\n"
            f"ANTHROPIC_KEY={anthropic_key}\n"
            "Authorization: Bearer opaqueBearerTokenValue9988776655\n"
        )
        findings = self.scanner.scan_text(text)
        by_kind = {f.kind: [x.value for x in findings if x.kind == f.kind] for f in findings}
        self.assertIn("pem_private_key", by_kind)
        self.assertEqual(
            by_kind["stripe_api_key"],
            [stripe_sk, stripe_rk],
        )
        self.assertEqual(
            by_kind["slack_token"],
            [slack_bot, slack_user],
        )
        self.assertEqual(
            by_kind["google_api_key"],
            [google_key],
        )
        self.assertEqual(
            by_kind["anthropic_api_key"],
            [anthropic_key],
        )
        self.assertEqual(
            by_kind["bearer_token"],
            ["opaqueBearerTokenValue9988776655"],
        )

    def test_ignores_camelcase_regex_and_mime_outside_sensitive_context(self) -> None:
        code = (
            'HANDLER_CLASS = "SimpleHTTPRequestHandler"\n'
            ' SERIALIZER_NAME = " JSONWebSignatureSerializerConfiguration "\n'.strip() + "\n"
            'MIME_JSON_LD = "application/vnd.acme.custom+json"\n'
            'MIME_HTML_UTF8 = "text/html;charset=utf-8"\n'
            'HEX_TABLE = "0123456789ABCDEFabcdef"\n'
            'REGEX_PATTERN = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==)?$"\n'
        )
        self.assertEqual(self.scanner.scan_text(code), [])
        self.assertFalse(
            self.scanner._is_high_entropy_token(
                "SimpleHTTPRequestHandler", sensitive_context=False
            )
        )
        self.assertFalse(
            self.scanner._is_high_entropy_token(
                "application/vnd.acme.custom+json", sensitive_context=False
            )
        )
        self.assertFalse(
            self.scanner._is_high_entropy_token(
                "text/html;charset=utf-8", sensitive_context=False
            )
        )
        self.assertFalse(
            self.scanner._is_high_entropy_token(
                "0123456789ABCDEFabcdef", sensitive_context=True
            )
        )
        self.assertFalse(
            self.scanner._is_high_entropy_token(
                r"^(?:[A-Za-z0-9+/]{4})*$", sensitive_context=False
            )
        )

    def test_detects_non_python_sensitive_assignments_in_js_ts_go_yaml(self) -> None:
        non_python_code = (
            'export const MASTER_KEY = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";\n'
            'const config = { CLIENT_SECRET: "Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6" };\n'
            'apiSecret := "Qp8Wn7Vm6Cx5Zl4Kj3Hg2Fd1Sa0"\n'
        )
        findings = self.scanner.scan_text(non_python_code)
        self.assertEqual(
            [(f.kind, f.value, f.line) for f in findings],
            [
                ("high_entropy_token", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6", 1),
                ("high_entropy_token", "Zx9Kp2Lm4Nq7Rs1Tv8Wz3Yb6", 2),
                ("high_entropy_token", "Qp8Wn7Vm6Cx5Zl4Kj3Hg2Fd1Sa0", 3),
            ],
        )


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
