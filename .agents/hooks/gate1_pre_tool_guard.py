"""
VERITAS Gate 1 — Antigravity PreToolUse Hook (custo: 0 tokens de LLM).

Intercepta chamadas de `write_file` e `edit_file` antes que o código toque
no disco, aplicando deterministicamente:
  1. Padrões proibidos definidos em config/constraints.json
  2. Validação sintática AST para arquivos .py completos (write_file)
  3. Limite de tamanho de arquivo (max_file_bytes)

Contrato Antigravity PreToolUse:
  stdin  -> JSON camelCase com `toolCall.name`, `toolCall.args`, `cwd`
  stdout -> {"decision": "allow"} ou {"decision": "deny", "reason": "..."}
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path


def _allow() -> None:
    print(json.dumps({"decision": "allow"}))
    sys.exit(0)


def _deny(reason: str) -> None:
    print(json.dumps({"decision": "deny", "reason": reason}, ensure_ascii=False))
    sys.exit(0)


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        _allow()

    tool_call = payload.get("toolCall") or {}
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args") or {}

    target_path_str = args.get("Path", "")
    if not target_path_str:
        _allow()

    norm_path = target_path_str.replace("\\", "/")

    # Não bloqueia arquivos de configuração do próprio hook, testes ou documentação
    exempt_markers = (
        "/config/constraints.json",
        "/.agents/",
        "/tests/",
        "/examples/demo_pipeline.py",
    )
    if any(marker in norm_path for marker in exempt_markers) or norm_path.endswith(".md"):
        _allow()

    # Localiza config/constraints.json a partir do diretório raiz do workspace
    workspace_root = Path(__file__).resolve().parent.parent.parent
    constraints_file = workspace_root / "config" / "constraints.json"
    if not constraints_file.exists():
        _allow()

    raw_constraints = json.loads(constraints_file.read_text(encoding="utf-8"))
    max_file_bytes = int(raw_constraints.get("max_file_bytes", 100_000))
    banned_patterns = raw_constraints.get("banned_patterns", [])

    content = args.get("Content") if tool_name == "write_file" else args.get("Replacement", "")
    if not isinstance(content, str):
        _allow()

    violations: list[str] = []

    if len(content.encode("utf-8")) > max_file_bytes:
        violations.append(f"[MAX_FILE_SIZE] Conteúdo excede {max_file_bytes} bytes.")

    # Validação sintática completa apenas em write_file (edit_file envia trecho parcial)
    if tool_name == "write_file" and norm_path.endswith(".py"):
        try:
            ast.parse(content, filename=target_path_str)
        except SyntaxError as exc:
            violations.append(f"[SYNTAX_ERROR] Linha {exc.lineno}: {exc.msg}")

    for line_no, line_text in enumerate(content.splitlines(), start=1):
        for rule in banned_patterns:
            if re.search(rule["pattern"], line_text):
                violations.append(
                    f"[{rule['id']}] Linha {line_no}: {rule['message']}"
                )

    if violations:
        summary = " | ".join(violations[:4])
        _deny(f"[VERITAS Gate 1 Bloqueado] {summary}")

    _allow()


if __name__ == "__main__":
    main()
