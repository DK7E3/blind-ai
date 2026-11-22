"""
VERITAS Runtime Verifier CLI (Multi-Modo) para o projeto `blind-ai`.

Suporta 3 modos de validação em tempo de execução (Gate 3) definidos no Feature Map:
  - unit_only   : Gate 1 (Hard Constraints) + Gate 2 (Testes unitários/benchmark)
  - cli_command : Gate 1 + Gate 2 + execução real do comando CLI (`python -m blind_ai ...`)
  - http_server : Gate 1 + Gate 2 + subida do Proxy HTTP real em porta efêmera + probes ao vivo

Sempre injeta PYTHONPATH=src automaticamente e retorna um JSON compacto (EvidenceBundle).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from framework.constraints import HardConstraintEngine
from framework.schemas import ExecutionPatch, ProbeSpec, WorkOrder
from framework.token_budget import compact_text


def _env_with_src(pythonpath_rel: str) -> dict[str, str]:
    env = os.environ.copy()
    src_path = str((WORKSPACE_ROOT / pythonpath_rel).resolve())
    prev = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{prev}" if prev else src_path
    return env


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_http_probes(
    entrypoint: list[str],
    health_path: str,
    probes: list[ProbeSpec],
    env: dict[str, str],
) -> tuple[bool, int, str, list[str]]:
    t0 = time.perf_counter()
    port = _find_free_port()
    cmd = [
        sys.executable if tok == "{python}" else tok.replace("{port}", str(port))
        for tok in entrypoint
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(WORKSPACE_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10.0
        health_url = f"http://127.0.0.1:{port}{health_path}"
        ready = False
        last_err = "timeout aguardando healthcheck"
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                last_err = f"Servidor encerrou prematuramente (exit={proc.returncode})."
                break
            try:
                with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                    if 200 <= resp.status < 300:
                        ready = True
                        break
            except Exception as exc:
                last_err = str(exc)
            time.sleep(0.15)

        if not ready:
            proc.terminate()
            out, err = proc.communicate(timeout=3)
            ms = int((time.perf_counter() - t0) * 1000)
            return False, ms, "Proxy HTTP falhou ao subir.", [last_err, compact_text(err or out, 300)]

        failures: list[str] = []
        for p in probes:
            url = f"http://127.0.0.1:{port}{p.path}"
            data = json.dumps(p.payload).encode("utf-8") if p.payload is not None else None
            headers = {"Content-Type": "application/json"} if data is not None else {}
            req = urllib.request.Request(url, data=data, headers=headers, method=p.method)
            try:
                with urllib.request.urlopen(req, timeout=p.timeout_seconds) as resp:
                    status, body = resp.status, resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as err:
                status, body = err.code, err.read().decode("utf-8", errors="replace")
            except Exception as exc:
                failures.append(f"{p.name}: erro de conexão ({exc})")
                continue

            if status != p.expected_status:
                failures.append(f"{p.name}: HTTP {status} != {p.expected_status} | {compact_text(body, 140)}")
                continue
            if p.expected_body_contains and p.expected_body_contains not in body:
                failures.append(f"{p.name}: body não contém '{p.expected_body_contains}'")
                continue
            if p.expected_json_subset:
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError as exc:
                    failures.append(f"{p.name}: JSON inválido ({exc})")
                    continue
                for k, v in p.expected_json_subset.items():
                    if not isinstance(parsed, dict) or parsed.get(k) != v:
                        failures.append(f"{p.name}: JSON['{k}'] != {v!r}")

        ms = int((time.perf_counter() - t0) * 1000)
        if failures:
            return False, ms, f"{len(failures)}/{len(probes)} probe(s) falharam.", failures
        return True, ms, f"{len(probes)}/{len(probes)} probe(s) validados ao vivo no Proxy HTTP.", []
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=3)


def verify_feature(feature_key: str, raw_cfg: dict, constraints: HardConstraintEngine) -> dict:
    if feature_key not in raw_cfg["features"]:
        return {"feature": feature_key, "passed": False, "feedback": f"Feature '{feature_key}' inexistente."}

    fcfg = raw_cfg["features"][feature_key]
    pythonpath_rel = raw_cfg.get("runtime", {}).get("pythonpath", "src")
    env = _env_with_src(pythonpath_rel)
    gates: list[dict] = []

    # 1. Verifica existência dos arquivos no disco e roda Gate 1 (Hard Constraints)
    files_content: dict[str, str] = {}
    missing = []
    for rel in fcfg["files"]:
        full = WORKSPACE_ROOT / rel
        if not full.exists():
            missing.append(rel)
        else:
            files_content[rel] = full.read_text(encoding="utf-8")

    if missing:
        return {
            "feature": feature_key,
            "domain": fcfg["domain"],
            "passed": False,
            "gates": [{"gate": "gate_1_hard_constraints", "ok": False, "ms": 0, "summary": f"Arquivos ausentes: {missing}"}],
            "feedback": f"GATE 1 FALHOU: arquivos ausentes no disco: {missing}",
        }

    # Ignora testes na checagem de padrões proibidos (datasets sintéticos contêm segredos fictícios)
    prod_files = {k: v for k, v in files_content.items() if not k.startswith("tests/")}
    t0 = time.perf_counter()
    if prod_files:
        wo = WorkOrder(
            work_order_id=f"VERIFY-{feature_key}",
            objective_id="AUTONOMOUS",
            domain=fcfg["domain"],
            feature_key=feature_key,
            summary=fcfg["description"],
            allowed_files=list(prod_files.keys()),
            acceptance_criteria=fcfg.get("invariants", []),
            probes=[],
        )
        violations = constraints.validate(
            wo,
            ExecutionPatch(wo.work_order_id, 1, prod_files, "verify"),
        )
    else:
        violations = []
    g1_ms = int((time.perf_counter() - t0) * 1000)
    if violations:
        details = [f"[{v.rule_id}] {v.file_path}:{v.line or 0} - {v.message}" for v in violations]
        gates.append({"gate": "gate_1_hard_constraints", "ok": False, "ms": g1_ms, "summary": f"{len(violations)} violação(ões)."})
        return {
            "feature": feature_key,
            "domain": fcfg["domain"],
            "passed": False,
            "gates": gates,
            "feedback": "GATE 1 FALHOU: " + " | ".join(details[:4]),
        }
    gates.append({"gate": "gate_1_hard_constraints", "ok": True, "ms": g1_ms, "summary": "Sintaxe e hard constraints OK."})

    # 2. Gate 2 — Testes unitários / benchmark
    unit_cmd = fcfg.get("unit_test_command", [])
    if unit_cmd:
        t0 = time.perf_counter()
        resolved = [sys.executable if tok == "{python}" else tok for tok in unit_cmd]
        proc = subprocess.run(resolved, cwd=str(WORKSPACE_ROOT), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        g2_ms = int((time.perf_counter() - t0) * 1000)
        if proc.returncode != 0:
            err_tail = compact_text((proc.stdout or "") + "\n" + (proc.stderr or ""), 450)
            gates.append({"gate": "gate_2_unit_tests", "ok": False, "ms": g2_ms, "summary": f"exit={proc.returncode}"})
            return {
                "feature": feature_key,
                "domain": fcfg["domain"],
                "passed": False,
                "gates": gates,
                "feedback": f"GATE 2 FALHOU (exit={proc.returncode}): {err_tail}",
            }
        gates.append({"gate": "gate_2_unit_tests", "ok": True, "ms": g2_ms, "summary": "Testes unitários aprovados."})

    # 3. Gate 3 — Validação em tempo de execução real (CLI ou HTTP Server)
    mode = fcfg.get("runtime_mode", "unit_only")
    if mode == "cli_command":
        t0 = time.perf_counter()
        cli_cmd = [sys.executable if tok == "{python}" else tok for tok in fcfg["cli_probe_command"]]
        proc = subprocess.run(cli_cmd, cwd=str(WORKSPACE_ROOT), env=env, capture_output=True, text=True, timeout=30)
        g3_ms = int((time.perf_counter() - t0) * 1000)
        if proc.returncode != 0:
            err_tail = compact_text((proc.stdout or "") + "\n" + (proc.stderr or ""), 400)
            gates.append({"gate": "gate_3_cli_runtime", "ok": False, "ms": g3_ms, "summary": f"CLI exit={proc.returncode}"})
            return {
                "feature": feature_key,
                "domain": fcfg["domain"],
                "passed": False,
                "gates": gates,
                "feedback": f"GATE 3 (CLI REAL) FALHOU: {err_tail}",
            }
        gates.append({"gate": "gate_3_cli_runtime", "ok": True, "ms": g3_ms, "summary": "CLI real executada com sucesso."})

    elif mode == "http_server":
        probes = [
            ProbeSpec(
                name=p["name"],
                method=p.get("method", "GET"),
                path=p["path"],
                expected_status=p.get("expected_status", 200),
                expected_json_subset=p.get("expected_json_subset", {}),
                expected_body_contains=p.get("expected_body_contains"),
                payload=p.get("payload"),
            )
            for p in fcfg.get("probes", [])
        ]
        ok, g3_ms, summary, details = _run_http_probes(
            raw_cfg["runtime"]["entrypoint"],
            raw_cfg["runtime"].get("health_path", "/health"),
            probes,
            env,
        )
        gates.append({"gate": "gate_3_http_runtime", "ok": ok, "ms": g3_ms, "summary": summary})
        if not ok:
            return {
                "feature": feature_key,
                "domain": fcfg["domain"],
                "passed": False,
                "gates": gates,
                "feedback": f"GATE 3 (PROXY HTTP REAL) FALHOU: {summary} | {' | '.join(details[:3])}",
            }

    return {
        "feature": feature_key,
        "domain": fcfg["domain"],
        "passed": True,
        "gates": gates,
        "feedback": "TODOS OS GATES APROVADOS.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--feature")
    group.add_argument("--all", action="store_true")
    args = parser.parse_args()

    raw_cfg = json.loads((WORKSPACE_ROOT / "config" / "feature_map.json").read_text(encoding="utf-8"))
    constraints = HardConstraintEngine.from_file(WORKSPACE_ROOT / "config" / "constraints.json")
    keys = list(raw_cfg["features"].keys()) if args.all else [args.feature]
    results = [verify_feature(k, raw_cfg, constraints) for k in keys]
    all_passed = all(r["passed"] for r in results)

    print(json.dumps({"passed": all_passed, "results": results}, indent=2, ensure_ascii=True))
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
