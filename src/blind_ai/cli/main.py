"""Command-line interface for Blind AI (``python -m blind_ai``).

Uses only the Python 3.12 standard library and exposes ``scan``, ``sanitize``,
``restore``, and ``benchmark`` subcommands.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Any

from blind_ai.core.benchmark import (
    BenchmarkMetrics,
    build_synthetic_dataset,
    evaluate_detector,
)
from blind_ai.core.file_filter import FileFilter
from blind_ai.core.scanner import DeterministicScanner
from blind_ai.core.vault import PseudonymVault


def _read_input_text(source: str) -> str:
    """Read UTF-8 text from stdin (``'-'``) or a file path."""
    if source == "-":
        return sys.stdin.read()
    return Path(source).read_text(encoding="utf-8")


def _write_output_text(text: str, output_path: str | None) -> None:
    """Write UTF-8 text to *output_path* or stdout if omitted."""
    if output_path is None or output_path == "-":
        sys.stdout.write(text)
        return
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _collect_scan_targets(raw_paths: Sequence[str]) -> tuple[list[Path | str], list[str]]:
    """Expand file/directory arguments into scan targets and missing-path errors."""
    targets: list[Path | str] = []
    missing: list[str] = []

    effective_paths = raw_paths if raw_paths else ("-",)
    for raw in effective_paths:
        if raw == "-":
            targets.append("-")
            continue
        path_obj = Path(raw)
        if not path_obj.exists():
            missing.append(raw)
            continue
        if path_obj.is_dir():
            for child in sorted(p for p in path_obj.rglob("*") if p.is_file()):
                targets.append(child)
        else:
            targets.append(path_obj)

    return targets, missing


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the ``scan`` subcommand."""
    targets, missing = _collect_scan_targets(args.paths)
    if missing:
        for path_str in missing:
            sys.stderr.write(f"Error: path not found: {path_str}\n")
        return 2

    file_filter = FileFilter()
    scanner = DeterministicScanner()

    blocked_files: list[dict[str, Any]] = []
    findings_payload: list[dict[str, Any]] = []

    for target in targets:
        if target == "-":
            text = sys.stdin.read()
            source_label = "<stdin>"
        else:
            assert isinstance(target, Path)
            decision = file_filter.check_path(target)
            if not decision.allowed:
                blocked_files.append(
                    {
                        "path": str(target),
                        "reason": decision.reason,
                        "matched_pattern": decision.matched_pattern,
                    }
                )
                continue
            try:
                text = target.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                sys.stderr.write(f"Error reading {target}: {exc}\n")
                return 2
            source_label = str(target)

        for finding in scanner.scan_text(text):
            findings_payload.append(
                {
                    "path": source_label,
                    "kind": finding.kind,
                    "value": finding.value,
                    "line": finding.line,
                    "start": finding.start,
                    "end": finding.end,
                    "source": finding.source,
                    "confidence": finding.confidence,
                }
            )

    if args.format == "json":
        report = {
            "findings": findings_payload,
            "blocked_files": blocked_files,
            "total_findings": len(findings_payload),
            "total_blocked": len(blocked_files),
            "strict": bool(args.strict),
        }
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    else:
        lines: list[str] = []
        for blocked in blocked_files:
            lines.append(f"[BLOCKED] {blocked['path']}: {blocked['reason']}")
        for item in findings_payload:
            lines.append(
                f"[FINDING] {item['path']}:{item['line']} "
                f"kind={item['kind']} source={item['source']} "
                f"confidence={item['confidence']:.2f} value={item['value']}"
            )
        if not lines:
            lines.append("No sensitive findings or blocked files detected.")
        else:
            lines.append(
                f"Summary: {len(findings_payload)} finding(s), "
                f"{len(blocked_files)} blocked file(s)."
            )
        sys.stdout.write("\n".join(lines) + "\n")

    if args.strict and (findings_payload or blocked_files):
        return 1
    return 0


def _cmd_sanitize(args: argparse.Namespace) -> int:
    """Execute the ``sanitize`` subcommand."""
    vault_path = Path(args.vault)
    try:
        if vault_path.exists():
            vault = PseudonymVault.load(vault_path)
        else:
            vault = PseudonymVault()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Error loading vault {vault_path}: {exc}\n")
        return 1

    try:
        raw_text = _read_input_text(args.input)
    except OSError as exc:
        sys.stderr.write(f"Error reading input {args.input}: {exc}\n")
        return 1

    sanitized_text = vault.sanitize(raw_text)

    try:
        vault.save(vault_path)
    except OSError as exc:
        sys.stderr.write(f"Error saving vault {vault_path}: {exc}\n")
        return 1

    try:
        _write_output_text(sanitized_text, args.output)
    except OSError as exc:
        sys.stderr.write(f"Error writing output {args.output}: {exc}\n")
        return 1

    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    """Execute the ``restore`` subcommand."""
    vault_path = Path(args.vault)
    if not vault_path.exists():
        sys.stderr.write(f"Error: vault file not found: {vault_path}\n")
        return 1

    try:
        vault = PseudonymVault.load(vault_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Error loading vault {vault_path}: {exc}\n")
        return 1

    try:
        sanitized_text = _read_input_text(args.input)
    except OSError as exc:
        sys.stderr.write(f"Error reading input {args.input}: {exc}\n")
        return 1

    restored_text = vault.restore(sanitized_text)

    try:
        _write_output_text(restored_text, args.output)
    except OSError as exc:
        sys.stderr.write(f"Error writing output {args.output}: {exc}\n")
        return 1

    return 0


def _metrics_to_dict(metrics: BenchmarkMetrics, dataset_size: int) -> dict[str, Any]:
    payload = asdict(metrics)
    payload["dataset_size"] = dataset_size
    return payload


def _cmd_benchmark(args: argparse.Namespace) -> int:
    """Execute the ``benchmark`` subcommand."""
    scanner = DeterministicScanner()
    dataset = build_synthetic_dataset()
    structured_subset = [case for case in dataset if case.category == "structured"]

    overall_metrics = evaluate_detector(scanner.scan_text, dataset)
    structured_metrics = evaluate_detector(scanner.scan_text, structured_subset)

    if args.format == "json":
        payload = {
            "overall": _metrics_to_dict(overall_metrics, len(dataset)),
            "h1_structured": _metrics_to_dict(
                structured_metrics, len(structured_subset)
            ),
        }
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    else:
        lines = [
            f"Blind AI Benchmark (overall, n={len(dataset)}):",
            f"  recall: {overall_metrics.recall:.4f}",
            f"  precision: {overall_metrics.precision:.4f}",
            f"  avg_latency_ms: {overall_metrics.avg_latency_ms:.4f}",
            (
                f"  tp={overall_metrics.tp} fp={overall_metrics.fp} "
                f"fn={overall_metrics.fn} tn={overall_metrics.tn}"
            ),
            f"Blind AI Benchmark H1 (structured, n={len(structured_subset)}):",
            f"  recall: {structured_metrics.recall:.4f}",
            f"  precision: {structured_metrics.precision:.4f}",
            f"  avg_latency_ms: {structured_metrics.avg_latency_ms:.4f}",
            (
                f"  tp={structured_metrics.tp} fp={structured_metrics.fp} "
                f"fn={structured_metrics.fn} tn={structured_metrics.tn}"
            ),
        ]
        sys.stdout.write("\n".join(lines) + "\n")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="blind_ai",
        description="Blind AI — local deterministic secret scanner and pseudonymization CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan files, directories, or stdin ('-') for sensitive data.",
    )
    scan_parser.add_argument(
        "paths",
        nargs="*",
        help="File/directory paths to scan, or '-' for stdin (default: '-').",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 if any finding or blocked file is detected.",
    )
    scan_parser.set_defaults(handler=_cmd_scan)

    sanitize_parser = subparsers.add_parser(
        "sanitize",
        help="Pseudonymize sensitive values in text using a local vault file.",
    )
    sanitize_parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Input file path or '-' for stdin (default: '-').",
    )
    sanitize_parser.add_argument(
        "--vault",
        required=True,
        help="Path to the local JSON pseudonym vault file.",
    )
    sanitize_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: stdout).",
    )
    sanitize_parser.set_defaults(handler=_cmd_sanitize)

    restore_parser = subparsers.add_parser(
        "restore",
        help="Restore pseudonymized placeholders using a local vault file.",
    )
    restore_parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Sanitized input file path or '-' for stdin (default: '-').",
    )
    restore_parser.add_argument(
        "--vault",
        required=True,
        help="Path to the existing local JSON pseudonym vault file.",
    )
    restore_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: stdout).",
    )
    restore_parser.set_defaults(handler=_cmd_restore)

    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="Run the synthetic benchmark dataset and report H1 metrics.",
    )
    benchmark_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    benchmark_parser.set_defaults(handler=_cmd_benchmark)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning a POSIX-style exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.handler(args))
