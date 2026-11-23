"""
VERITAS Autonomous Backlog Runner — Execução Multi-Agente Desassistida no Antigravity.

Consome `config/backlog.json` tarefa por tarefa respeitando dependências:
  1. Coordenador (determinístico, 0 tokens): seleciona a próxima tarefa `pending` pronta.
  2. Gerente de Projeto (model="flash"): gera WorkOrder concisa a partir do Feature Map.
  3. Agente Executor (contexto persistente entre retries): implementa APENAS `allowed_files`.
  4. Runtime Verifier (0 tokens): roda Gate 1 + Gate 2 + Gate 3 (testes, CLI ou Proxy HTTP real).
  5. PM Evidence Review (model="flash"): aprova somente se `passed == true`.
  6. Persistência imediata: atualiza `config/backlog.json` e `logs/mission_log.md` após cada tarefa.

Args opcionais:
  {"max_tasks": 7, "max_retries": 3}
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

workspace = Path.cwd()
backlog_path = workspace / "config" / "backlog.json"
feature_map_path = workspace / "config" / "feature_map.json"
mission_log_path = workspace / "logs" / "mission_log.md"
verifier_script = workspace / ".agents" / "skills" / "veritas-orchestrator" / "scripts" / "verify_runtime.py"

max_tasks = int(args.get("max_tasks", 7))
max_retries = int(args.get("max_retries", 3))

PM_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "instructions": {"type": "string"},
        "verification_focus": {"type": "string"},
    },
    "required": ["instructions", "verification_focus"],
}

EXECUTOR_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "modified_files": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "modified_files"],
}

PM_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["approved", "escalated"]},
        "note": {"type": "string"},
    },
    "required": ["status", "note"],
}


def load_backlog():
    return json.loads(backlog_path.read_text(encoding="utf-8"))


def save_backlog(data):
    backlog_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def append_mission_log(entry_md):
    mission_log_path.parent.mkdir(parents=True, exist_ok=True)
    if not mission_log_path.exists():
        mission_log_path.write_text("# VERITAS — Diário Autônomo de Execução (`blind-ai`)\n\n", encoding="utf-8")
    with mission_log_path.open("a", encoding="utf-8") as f:
        f.write(entry_md + "\n")


def find_next_ready_task(backlog):
    approved_ids = {t["id"] for t in backlog["tasks"] if t["status"] == "approved"}
    for task in backlog["tasks"]:
        if task["status"] == "pending":
            deps = task.get("depends_on", [])
            if all(d in approved_ids for d in deps):
                return task
    return None


def run_verifier(feature_key):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, str(verifier_script), "--feature", feature_key],
        cwd=str(workspace),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    raw_out = proc.stdout or ""
    raw_err = proc.stderr or ""
    try:
        return json.loads(raw_out)
    except json.JSONDecodeError:
        return {
            "passed": False,
            "results": [{"feature": feature_key, "passed": False, "feedback": (raw_err or raw_out)[:400]}],
        }


feature_map = json.loads(feature_map_path.read_text(encoding="utf-8"))["features"]
executed_summary = []

for step_idx in range(max_tasks):
    backlog = load_backlog()
    task = find_next_ready_task(backlog)
    if task is None:
        log("Nenhuma tarefa pendente pronta para execução. Encerrando ciclo autônomo.")
        break

    tid = task["id"]
    fkey = task["feature_key"]
    fcfg = feature_map[fkey]
    domain = fcfg["domain"]
    allowed = fcfg["files"]

    phase(f"{tid} ({task['phase']}) — {fkey}")
    task["status"] = "in_progress"
    save_backlog(backlog)

    # 1. PM Plan determinístico a partir do Feature Map (0 tokens de LLM — economia estrutural)
    invariants_bullets = "\n".join(f"- {inv}" for inv in fcfg["invariants"])
    pm_instructions = (
        f"Objetivo ({tid}): {task['title']}\n"
        f"Especificação: {fcfg['description']}\n"
        f"Arquivos permitidos: {allowed}\n"
        f"Invariantes obrigatórias:\n{invariants_bullets}"
    )

    # 2. Executor com contexto persistente + loop de auto-correção
    worker = agent(
        prompt=(
            f"Você é o Agente Executor VERITAS do domínio '{domain}' no projeto blind-ai.\n"
            f"Workspace: {workspace}\n"
            f"REGRA INVIOLÁVEL: edite/crie APENAS os arquivos listados em {allowed}.\n"
            "Use Python 3.12 com biblioteca padrão (sem exigir pip install externo). "
            "Mantenha 100% de compatibilidade com os testes existentes do projeto."
        ),
        role=f"Executor ({tid})",
        model="inherit",
    )

    feedback = None
    last_evidence = None
    attempts = 0

    for attempt in range(1, max_retries + 1):
        attempts = attempt
        turn_prompt = (
            f"Tentativa {attempt}/{max_retries} — {tid}: {task['title']}\n"
            f"{pm_instructions}\n"
        )
        if feedback:
            turn_prompt += f"FEEDBACK COMPACTO DO VERIFICADOR (corrija a causa raiz): {feedback}\n"

        exec_res = await worker(turn_prompt, EXECUTOR_SCHEMA)
        log(f"[{tid}] Tentativa {attempt}: {exec_res['summary']}")

        # 3. Verificação determinística em runtime real (0 tokens)
        evidence = run_verifier(fkey)
        last_evidence = evidence
        if evidence.get("passed"):
            log(f"[{tid}] APROVADO em runtime real na tentativa {attempt}.")
            break

        res0 = evidence["results"][0] if evidence.get("results") else {}
        feedback = res0.get("feedback", "Falha na verificação.")
        log(f"[{tid}] Falha na tentativa {attempt}: {feedback}")

    del worker

    # 4. Revisão determinística por evidência (0 tokens de LLM)
    passed = bool(last_evidence and last_evidence.get("passed"))
    res0 = last_evidence["results"][0] if (last_evidence and last_evidence.get("results")) else {}
    gates_summary = ", ".join(
        f"{g['gate']}={'ok' if g['ok'] else 'fail'}({g['ms']}ms)"
        for g in res0.get("gates", [])
    )
    review = {
        "status": "approved" if passed else "escalated",
        "note": (
            f"Aprovado por evidência determinística ({gates_summary})."
            if passed
            else f"Escalonado após {attempts} tentativas: {res0.get('feedback', 'falha')}"
        ),
    }

    # 5. Persistência imediata do estado
    backlog = load_backlog()
    for t in backlog["tasks"]:
        if t["id"] == tid:
            t["status"] = review["status"]
            t["attempts"] = attempts
            t["last_note"] = review["note"]
            break
    save_backlog(backlog)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_mission_log(
        f"## [{ts}] {tid} — `{fkey}` (`{review['status'].upper()}`)\n"
        f"- **Tentativas:** {attempts}/{max_retries}\n"
        f"- **Nota do PM:** {review['note']}\n"
        f"- **Evidência:** `{json.dumps(last_evidence, ensure_ascii=False)}`\n"
    )

    executed_summary.append(
        {"id": tid, "feature": fkey, "status": review["status"], "attempts": attempts, "note": review["note"]}
    )

phase("Resumo do Ciclo Autônomo")
print(json.dumps({"executed": executed_summary}, indent=2, ensure_ascii=False))
