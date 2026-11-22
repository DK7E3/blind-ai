---
name: veritas-orchestrator
description: >-
  Executa o fluxo autônomo VERITAS sobre o backlog do projeto blind-ai dentro
  do Antigravity (Coordenador -> PMs em flash -> Executores -> Validação em
  Runtime Real -> Persistência em backlog.json e logs/mission_log.md).
---

# VERITAS Autônomo — Projeto `blind-ai`

## Como executar o time autônomo
Dispare o workflow dinâmico diretamente via `run_workflow`:

```text
run_workflow(
  ScriptPath="c:/Users/franc/Downloads/time de inteligencia artificial/blind-ai-veritas/.agents/workflows/veritas_autonomous.py",
  Cwd="c:/Users/franc/Downloads/time de inteligencia artificial/blind-ai-veritas",
  Args={"max_tasks": 7, "max_retries": 3},
  Description="Execução autônoma VERITAS do backlog do blind-ai"
)
```

## Verificação manual de uma feature
```powershell
python .agents/skills/veritas-orchestrator/scripts/verify_runtime.py --feature <feature_key>
```
