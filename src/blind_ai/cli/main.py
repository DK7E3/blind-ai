"""Command-line interface for Blind AI (``python -m blind_ai``).

Uses only the Python 3.12 standard library and exposes ``scan``, ``sanitize``,
``restore``, ``pack``, ``proxy``, and ``benchmark`` subcommands.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any

from blind_ai.core.benchmark import (
    BenchmarkMetrics,
    build_synthetic_dataset,
    evaluate_detector,
)
from blind_ai.core.config import BlindAIConfig
from blind_ai.core.packer import ContextPacker
from blind_ai.core.scanner import DeterministicScanner, Finding
from blind_ai.core.secure_vault import load_encrypted, save_encrypted
from blind_ai.core.vault import PseudonymVault
from blind_ai.proxy import server as proxy_server


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


def _load_config(
    config_path: str | None,
    *,
    start_dir: str | Path | None = None,
) -> BlindAIConfig:
    """Load configuration from an explicit ``--config`` file or auto-discover it."""
    if config_path is not None:
        path_obj = Path(config_path)
        if not path_obj.is_file():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        return BlindAIConfig.from_toml(path_obj)
    return BlindAIConfig.discover(start_dir)


def _scan_with_config(
    scanner: DeterministicScanner,
    text: str,
    cfg: BlindAIConfig,
) -> list[Finding]:
    """Scan *text* applying built-in rules, config custom regexes, and allowlist."""
    findings = list(scanner.scan_text(text))
    if cfg.compiled_custom_rules:
        occupied = [(finding.start, finding.end) for finding in findings]
        for rule_name, pattern in cfg.compiled_custom_rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                if start == end:
                    continue
                if any(
                    start < occ_end and occ_start < end
                    for occ_start, occ_end in occupied
                ):
                    continue
                occupied.append((start, end))
                findings.append(
                    Finding(
                        kind=rule_name,
                        value=match.group(0),
                        start=start,
                        end=end,
                        line=text.count("\n", 0, start) + 1,
                        source="custom_rule",
                        confidence=0.95,
                    )
                )
        findings.sort(key=lambda item: (item.start, item.end, item.kind))
    return cfg.filter_findings(findings)


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


def _collect_staged_targets() -> tuple[list[Path], str | None]:
    """Collect git-staged files via ``git diff --cached --name-only --diff-filter=ACMR``."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return [], f"Error executing git: {exc}"

    if result.returncode != 0:
        detail = result.stderr.strip() or f"git exited with status {result.returncode}"
        return [], f"Error listing staged files: {detail}"

    targets = [
        Path(line)
        for line in (raw.strip() for raw in result.stdout.splitlines())
        if line
    ]
    return targets, None


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the ``scan`` subcommand."""
    start_dir: Path | None = None
    for raw in args.paths:
        if raw != "-":
            start_dir = Path(raw)
            break

    try:
        cfg = _load_config(args.config, start_dir=start_dir)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        sys.stderr.write(f"Error loading config: {exc}\n")
        return 2

    targets: list[Path | str] = []
    if args.staged:
        staged_targets, git_error = _collect_staged_targets()
        if git_error is not None:
            sys.stderr.write(f"{git_error}\n")
            return 2
        targets.extend(staged_targets)
        if args.paths:
            extra_targets, missing = _collect_scan_targets(args.paths)
            if missing:
                for path_str in missing:
                    sys.stderr.write(f"Error: path not found: {path_str}\n")
                return 2
            targets.extend(extra_targets)
    else:
        targets, missing = _collect_scan_targets(args.paths)
        if missing:
            for path_str in missing:
                sys.stderr.write(f"Error: path not found: {path_str}\n")
            return 2

    file_filter = cfg.build_file_filter()
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

        for finding in _scan_with_config(scanner, text, cfg):
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
    start_dir = None if args.input == "-" else args.input
    try:
        cfg = _load_config(args.config, start_dir=start_dir)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        sys.stderr.write(f"Error loading config: {exc}\n")
        return 2

    vault_path = Path(args.vault)
    try:
        if vault_path.exists():
            if args.passphrase is not None:
                vault = load_encrypted(vault_path, args.passphrase)
            else:
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

    findings = _scan_with_config(DeterministicScanner(), raw_text, cfg)
    sanitized_text = vault.sanitize(raw_text, findings=findings)

    try:
        if args.passphrase is not None:
            save_encrypted(vault, vault_path, args.passphrase)
        else:
            vault.save(vault_path)
    except (OSError, ValueError) as exc:
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
    if args.config is not None:
        try:
            _load_config(args.config)
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            sys.stderr.write(f"Error loading config: {exc}\n")
            return 2

    vault_path = Path(args.vault)
    if not vault_path.exists():
        sys.stderr.write(f"Error: vault file not found: {vault_path}\n")
        return 1

    try:
        if args.passphrase is not None:
            vault = load_encrypted(vault_path, args.passphrase)
        else:
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


def _cmd_pack(args: argparse.Namespace) -> int:
    """Execute the ``pack`` subcommand."""
    try:
        cfg = _load_config(args.config, start_dir=args.directory)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        sys.stderr.write(f"Error loading config: {exc}\n")
        return 2

    packer = ContextPacker(
        file_filter=cfg.build_file_filter(),
        proprietary_terms=cfg.proprietary_terms,
    )
    try:
        result = packer.pack(args.directory)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"Error packing directory {args.directory}: {exc}\n")
        return 2

    vault_path = Path(args.vault) if args.vault is not None else None
    encrypted = vault_path is not None and args.passphrase is not None
    if vault_path is not None:
        try:
            if args.passphrase is not None:
                save_encrypted(result.vault, vault_path, args.passphrase)
            else:
                result.vault.save(vault_path)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"Error saving vault {vault_path}: {exc}\n")
            return 1

    if args.output is not None:
        try:
            _write_output_text(result.bundle, args.output)
        except OSError as exc:
            sys.stderr.write(f"Error writing output {args.output}: {exc}\n")
            return 1

    if args.as_json:
        summary = {
            "directory": str(Path(args.directory)),
            "output": str(args.output) if args.output is not None else None,
            "vault": str(vault_path) if vault_path is not None else None,
            "encrypted": encrypted,
            "session_id": result.vault.session_id,
            "included_count": result.included_count,
            "blocked_count": result.blocked_count,
            "estimated_tokens": result.estimated_tokens,
            "placeholders_count": len(result.vault.placeholder_to_value),
            "included_files": result.included_files,
            "blocked_files": result.blocked_files,
        }
        sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    elif args.output is None:
        sys.stdout.write(result.bundle)
    else:
        vault_info = (
            f" (vault: {vault_path} [{'encrypted' if encrypted else 'json'}])"
            if vault_path is not None
            else ""
        )
        sys.stdout.write(
            f"Packed {result.included_count} file(s) "
            f"({result.blocked_count} blocked, ~{result.estimated_tokens} tokens, "
            f"{len(result.vault.placeholder_to_value)} placeholder(s)) "
            f"-> {args.output}{vault_info}\n"
        )

    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    """Execute the ``proxy`` subcommand by delegating to ``blind_ai.proxy.server``."""
    proxy_args = list(args.proxy_args)
    if proxy_args and proxy_args[0] == "--":
        proxy_args = proxy_args[1:]
    return int(proxy_server.main(proxy_args))


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
        help="Scan files, directories, staged git changes, or stdin ('-') for sensitive data.",
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
    scan_parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan files currently staged in git (git diff --cached).",
    )
    scan_parser.add_argument(
        "--config",
        default=None,
        help="Optional path to a .blindai.toml configuration file.",
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
        help="Path to the local pseudonym vault file.",
    )
    sanitize_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: stdout).",
    )
    sanitize_parser.add_argument(
        "--passphrase",
        default=None,
        help="Optional passphrase for authenticated encrypted vault storage.",
    )
    sanitize_parser.add_argument(
        "--config",
        default=None,
        help="Optional path to a .blindai.toml configuration file.",
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
        help="Path to the existing local pseudonym vault file.",
    )
    restore_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: stdout).",
    )
    restore_parser.add_argument(
        "--passphrase",
        default=None,
        help="Optional passphrase for decrypting an encrypted vault file.",
    )
    restore_parser.add_argument(
        "--config",
        default=None,
        help="Optional path to a .blindai.toml configuration file.",
    )
    restore_parser.set_defaults(handler=_cmd_restore)

    pack_parser = subparsers.add_parser(
        "pack",
        help="Pack a repository directory into a sanitized Markdown context bundle.",
    )
    pack_parser.add_argument(
        "directory",
        metavar="dir",
        nargs="?",
        default=".",
        help="Directory to pack into a sanitized Markdown bundle (default: '.').",
    )
    pack_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Optional output file path for the sanitized Markdown bundle (default: stdout).",
    )
    pack_parser.add_argument(
        "--vault",
        default=None,
        help="Optional output path for the pseudonym vault file.",
    )
    pack_parser.add_argument(
        "--passphrase",
        default=None,
        help="Optional passphrase to encrypt the vault file.",
    )
    pack_parser.add_argument(
        "--config",
        default=None,
        help="Optional path to a .blindai.toml configuration file.",
    )
    pack_parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print pack summary as JSON to stdout.",
    )
    pack_parser.set_defaults(handler=_cmd_pack)

    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Launch the local Blind AI HTTP proxy/gateway server.",
        add_help=False,
    )
    proxy_parser.add_argument(
        "proxy_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to blind_ai.proxy.server.",
    )
    proxy_parser.set_defaults(handler=_cmd_proxy)

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
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    if raw_argv and raw_argv[0] == "proxy":
        proxy_args = raw_argv[1:]
        if proxy_args and proxy_args[0] == "--":
            proxy_args = proxy_args[1:]
        return int(proxy_server.main(proxy_args))
    parser = build_parser()
    args = parser.parse_args(raw_argv)
    return int(args.handler(args))
