"""
Motor determinístico de Hard Constraints (Gate 1 — custo zero de tokens).

Princípio arquitetural:
Regras críticas NÃO ficam apenas em prompts em linguagem natural (que modelos
podem ignorar). Elas são aplicadas deterministicamente por AST, regex e escopo
de arquivos antes mesmo de executar testes ou subir a aplicação.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path

from framework.schemas import ConstraintViolation, ExecutionPatch, WorkOrder


@dataclass(frozen=True)
class BannedPatternRule:
    rule_id: str
    pattern: str
    message: str


class HardConstraintEngine:
    """Valida escopo de escrita, sintaxe e padrões proibidos deterministicamente."""

    def __init__(
        self,
        banned_patterns: list[BannedPatternRule],
        max_file_bytes: int = 100_000,
    ) -> None:
        self._banned = [
            (r.rule_id, re.compile(r.pattern), r.message) for r in banned_patterns
        ]
        self._max_file_bytes = max_file_bytes

    @classmethod
    def from_file(cls, path: Path) -> HardConstraintEngine:
        raw = json.loads(path.read_text(encoding="utf-8"))
        rules = [
            BannedPatternRule(
                rule_id=item["id"],
                pattern=item["pattern"],
                message=item["message"],
            )
            for item in raw.get("banned_patterns", [])
        ]
        return cls(
            banned_patterns=rules,
            max_file_bytes=int(raw.get("max_file_bytes", 100_000)),
        )

    def validate(self, work_order: WorkOrder, patch: ExecutionPatch) -> list[ConstraintViolation]:
        violations: list[ConstraintViolation] = []
        allowed = {self._norm(p) for p in work_order.allowed_files}

        if not patch.modified_files:
            violations.append(
                ConstraintViolation(
                    rule_id="EMPTY_PATCH",
                    file_path="<patch>",
                    message="Patch não modificou nenhum arquivo.",
                )
            )
            return violations

        for rel_path, content in patch.modified_files.items():
            norm_path = self._norm(rel_path)

            # 1. Restrição estrita de escopo (isolamento de domínio)
            if norm_path not in allowed:
                violations.append(
                    ConstraintViolation(
                        rule_id="SCOPE_VIOLATION",
                        file_path=rel_path,
                        message=f"Arquivo fora do escopo permitido da WorkOrder ({sorted(allowed)}).",
                    )
                )
                continue

            # 2. Limite de tamanho para evitar bloat de contexto/código
            if len(content.encode("utf-8")) > self._max_file_bytes:
                violations.append(
                    ConstraintViolation(
                        rule_id="MAX_FILE_SIZE",
                        file_path=rel_path,
                        message=f"Arquivo excede o limite de {self._max_file_bytes} bytes.",
                    )
                )

            # 3. Validação sintática AST para arquivos Python
            if norm_path.endswith(".py"):
                try:
                    ast.parse(content, filename=rel_path)
                except SyntaxError as exc:
                    violations.append(
                        ConstraintViolation(
                            rule_id="SYNTAX_ERROR",
                            file_path=rel_path,
                            message=f"Erro de sintaxe Python: {exc.msg}",
                            line=exc.lineno,
                        )
                    )

            # 4. Padrões proibidos (anti-patterns, segredos, funções inseguras)
            for line_no, line_text in enumerate(content.splitlines(), start=1):
                for rule_id, compiled, message in self._banned:
                    if compiled.search(line_text):
                        violations.append(
                            ConstraintViolation(
                                rule_id=rule_id,
                                file_path=rel_path,
                                message=message,
                                line=line_no,
                            )
                        )

        return violations

    @staticmethod
    def _norm(path: str) -> str:
        return path.replace("\\", "/").lstrip("./")
