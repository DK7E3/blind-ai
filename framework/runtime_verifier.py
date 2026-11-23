"""
Harness de Verificação Multi-Camada com Validação em Tempo de Execução Real.

Fluxo obrigatório (Fail-Fast -> Economia de Tokens e Tempo):
  Gate 1: Hard Constraints determinísticos (escopo, AST, padrões proibidos)
  Gate 2: Testes unitários / contrato rápidos (quando definidos na feature)
  Gate 3: Execução da aplicação REAL em subprocesso isolado + probes HTTP/JSON ao vivo
  Rollback automático se qualquer gate falhar (o workspace nunca fica corrompido).
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from framework.constraints import HardConstraintEngine
from framework.feature_map import FeatureMap
from framework.schemas import (
    EvidenceBundle,
    ExecutionPatch,
    GateResult,
    ProbeSpec,
    WorkOrder,
)
from framework.token_budget import compact_text


class RuntimeVerifier:
    """Executa os 3 gates de verificação e emite um EvidenceBundle compacto."""

    def __init__(
        self,
        workspace_root: Path,
        feature_map: FeatureMap,
        constraints: HardConstraintEngine,
        startup_timeout_seconds: float = 10.0,
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.feature_map = feature_map
        self.constraints = constraints
        self.startup_timeout_seconds = startup_timeout_seconds

    def verify_patch(self, work_order: WorkOrder, patch: ExecutionPatch) -> EvidenceBundle:
        gates: list[GateResult] = []
        artifacts: dict[str, Any] = {}

        # --- GATE 1: Hard Constraints (antes mesmo de tocar no disco) ---
        t0 = time.perf_counter()
        violations = self.constraints.validate(work_order, patch)
        g1_ms = int((time.perf_counter() - t0) * 1000)
        if violations:
            details = [
                f"[{v.rule_id}] {v.file_path}"
                + (f":{v.line}" if v.line else "")
                + f" - {v.message}"
                for v in violations
            ]
            gates.append(
                GateResult(
                    gate_name="gate_1_hard_constraints",
                    passed=False,
                    duration_ms=g1_ms,
                    summary=f"{len(violations)} violação(ões) de hard constraint.",
                    details=details,
                )
            )
            return EvidenceBundle(
                work_order_id=work_order.work_order_id,
                attempt=patch.attempt,
                passed=False,
                gates=gates,
                compact_feedback="GATE 1 FALHOU: " + " | ".join(details[:5]),
            )

        gates.append(
            GateResult(
                gate_name="gate_1_hard_constraints",
                passed=True,
                duration_ms=g1_ms,
                summary="Escopo, sintaxe e padrões proibidos aprovados.",
            )
        )

        # Aplica o patch temporariamente com snapshot para rollback seguro
        backups = self._apply_patch_with_backup(patch)
        try:
            # --- GATE 2: Testes unitários/contrato (fail-fast) ---
            feature = self.feature_map.get(work_order.feature_key)
            if feature.unit_test_command:
                g2 = self._run_unit_tests(feature.unit_test_command)
                gates.append(g2)
                if not g2.passed:
                    self._rollback(backups)
                    return EvidenceBundle(
                        work_order_id=work_order.work_order_id,
                        attempt=patch.attempt,
                        passed=False,
                        gates=gates,
                        compact_feedback=f"GATE 2 FALHOU: {g2.summary} | {' '.join(g2.details[:3])}",
                    )
            else:
                gates.append(
                    GateResult(
                        gate_name="gate_2_unit_tests",
                        passed=True,
                        duration_ms=0,
                        summary="Nenhum teste unitário dedicado; seguindo para runtime real.",
                    )
                )

            # --- GATE 3: Validação em tempo de execução na aplicação REAL ---
            g3, runtime_info = self._run_real_app_probes(work_order.probes)
            gates.append(g3)
            artifacts["runtime"] = runtime_info
            if not g3.passed:
                self._rollback(backups)
                return EvidenceBundle(
                    work_order_id=work_order.work_order_id,
                    attempt=patch.attempt,
                    passed=False,
                    gates=gates,
                    runtime_artifacts=artifacts,
                    compact_feedback=f"GATE 3 (RUNTIME REAL) FALHOU: {g3.summary} | {' | '.join(g3.details[:4])}",
                )

            # Todos os gates passaram -> mantém o patch aplicado no disco
            return EvidenceBundle(
                work_order_id=work_order.work_order_id,
                attempt=patch.attempt,
                passed=True,
                gates=gates,
                runtime_artifacts=artifacts,
                compact_feedback="TODOS OS GATES APROVADOS (constraints + runtime real).",
            )
        except Exception as exc:
            self._rollback(backups)
            gates.append(
                GateResult(
                    gate_name="gate_3_runtime_validation",
                    passed=False,
                    duration_ms=0,
                    summary=f"Erro inesperado no harness de verificação: {exc}",
                )
            )
            return EvidenceBundle(
                work_order_id=work_order.work_order_id,
                attempt=patch.attempt,
                passed=False,
                gates=gates,
                compact_feedback=f"ERRO NO HARNESS: {compact_text(str(exc), 300)}",
            )

    def _apply_patch_with_backup(self, patch: ExecutionPatch) -> dict[Path, str | None]:
        backups: dict[Path, str | None] = {}
        for rel_path, new_content in patch.modified_files.items():
            full_path = (self.workspace_root / rel_path).resolve()
            if not str(full_path).startswith(str(self.workspace_root)):
                raise ValueError(f"Path traversal bloqueado: {rel_path}")
            backups[full_path] = (
                full_path.read_text(encoding="utf-8") if full_path.exists() else None
            )
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(new_content, encoding="utf-8")
        return backups

    def _rollback(self, backups: dict[Path, str | None]) -> None:
        for full_path, previous in backups.items():
            if previous is None:
                if full_path.exists():
                    full_path.unlink()
            else:
                full_path.write_text(previous, encoding="utf-8")

    def _run_unit_tests(self, command: list[str]) -> GateResult:
        t0 = time.perf_counter()
        resolved_cmd = [sys.executable if token == "{python}" else token for token in command]
        proc = subprocess.run(
            resolved_cmd,
            cwd=str(self.workspace_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        ms = int((time.perf_counter() - t0) * 1000)
        if proc.returncode == 0:
            return GateResult(
                gate_name="gate_2_unit_tests",
                passed=True,
                duration_ms=ms,
                summary="Testes unitários aprovados.",
            )
        combined = compact_text((proc.stdout or "") + "\n" + (proc.stderr or ""), 400)
        return GateResult(
            gate_name="gate_2_unit_tests",
            passed=False,
            duration_ms=ms,
            summary=f"Testes unitários falharam (exit={proc.returncode}).",
            details=[combined],
        )

    def _run_real_app_probes(self, probes: list[ProbeSpec]) -> tuple[GateResult, dict[str, Any]]:
        t0 = time.perf_counter()
        port = self._find_free_port()
        cmd = [
            sys.executable if token == "{python}" else token.replace("{port}", str(port))
            for token in self.feature_map.app_entrypoint
        ]

        proc = subprocess.Popen(
            cmd,
            cwd=str(self.workspace_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        runtime_info: dict[str, Any] = {"port": port, "probes": []}
        try:
            ready, readiness_err = self._wait_for_health(port, proc)
            if not ready:
                ms = int((time.perf_counter() - t0) * 1000)
                stdout_tail, stderr_tail = self._terminate_and_capture(proc)
                return (
                    GateResult(
                        gate_name="gate_3_runtime_validation",
                        passed=False,
                        duration_ms=ms,
                        summary="Aplicação real falhou ao inicializar.",
                        details=[
                            readiness_err,
                            compact_text(stderr_tail or stdout_tail, 350),
                        ],
                    ),
                    runtime_info,
                )

            failures: list[str] = []
            for probe in probes:
                ok, detail = self._execute_probe(port, probe)
                runtime_info["probes"].append({"name": probe.name, "ok": ok, "detail": detail})
                if not ok:
                    failures.append(f"{probe.name}: {detail}")

            ms = int((time.perf_counter() - t0) * 1000)
            if failures:
                return (
                    GateResult(
                        gate_name="gate_3_runtime_validation",
                        passed=False,
                        duration_ms=ms,
                        summary=f"{len(failures)}/{len(probes)} probe(s) falharam na aplicação real.",
                        details=failures,
                    ),
                    runtime_info,
                )

            return (
                GateResult(
                    gate_name="gate_3_runtime_validation",
                    passed=True,
                    duration_ms=ms,
                    summary=f"{len(probes)}/{len(probes)} probe(s) validados na aplicação real.",
                ),
                runtime_info,
            )
        finally:
            self._terminate_and_capture(proc)

    def _wait_for_health(
        self, port: int, proc: subprocess.Popen[str]
    ) -> tuple[bool, str]:
        deadline = time.monotonic() + self.startup_timeout_seconds
        url = f"http://127.0.0.1:{port}{self.feature_map.health_path}"
        last_error = "timeout aguardando healthcheck"
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False, f"Processo encerrou prematuramente com exit={proc.returncode}."
            try:
                with urllib.request.urlopen(url, timeout=1.0) as resp:
                    if 200 <= resp.status < 300:
                        return True, ""
            except Exception as exc:
                last_error = str(exc)
            time.sleep(0.15)
        return False, f"Healthcheck {url} falhou: {last_error}"

    def _execute_probe(self, port: int, probe: ProbeSpec) -> tuple[bool, str]:
        url = f"http://127.0.0.1:{port}{probe.path}"
        data = None
        headers = {}
        if probe.payload is not None:
            data = json.dumps(probe.payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=probe.method)
        try:
            with urllib.request.urlopen(req, timeout=probe.timeout_seconds) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as err:
            status = err.code
            body = err.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return False, f"Erro de conexão em {probe.method} {probe.path}: {exc}"

        if status != probe.expected_status:
            return (
                False,
                f"HTTP {status} != esperado {probe.expected_status} | body={compact_text(body, 180)}",
            )

        if probe.expected_body_contains and probe.expected_body_contains not in body:
            return (
                False,
                f"Body não contém '{probe.expected_body_contains}' | body={compact_text(body, 180)}",
            )

        if probe.expected_json_subset:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError as exc:
                return False, f"Resposta não é JSON válido: {exc}"
            for k, expected_v in probe.expected_json_subset.items():
                if not isinstance(parsed, dict) or parsed.get(k) != expected_v:
                    return (
                        False,
                        f"JSON['{k}']={parsed.get(k) if isinstance(parsed, dict) else None!r} != esperado {expected_v!r}",
                    )

        return True, f"HTTP {status} OK"

    @staticmethod
    def _find_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])

    @staticmethod
    def _terminate_and_capture(proc: subprocess.Popen[str]) -> tuple[str, str]:
        if proc.poll() is None:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=3)
                return stdout or "", stderr or ""
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=3)
                return stdout or "", stderr or ""
        stdout = proc.stdout.read() if proc.stdout else ""
        stderr = proc.stderr.read() if proc.stderr else ""
        return stdout, stderr
