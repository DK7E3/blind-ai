"""
Gestão de orçamento de tokens e compactação estrutural de contexto.

Garante economia de tokens a longo prazo por meio de:
1. Rastreamento por camada (Coordenador, PM, Executor) e por WorkOrder.
2. Circuit-breaker determinístico que interrompe loops improdutivos antes de estourar o orçamento.
3. Compactação de logs/erros para feedback denso em informação e curto em tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class TokenBudgetExceeded(RuntimeError):
    """Disparado quando uma tarefa ou objetivo ultrapassa o limite de tokens."""


@dataclass
class TokenLedger:
    """Livro-razão de consumo de tokens com circuit-breaker."""

    max_budget: int
    spent_by_role: dict[str, int] = field(default_factory=dict)
    spent_by_work_order: dict[str, int] = field(default_factory=dict)

    @property
    def total_spent(self) -> int:
        return sum(self.spent_by_role.values())

    @property
    def remaining(self) -> int:
        return max(0, self.max_budget - self.total_spent)

    def record(self, role: str, tokens: int, work_order_id: str | None = None) -> None:
        if tokens < 0:
            raise ValueError("Tokens consumidos não podem ser negativos.")
        self.spent_by_role[role] = self.spent_by_role.get(role, 0) + tokens
        if work_order_id:
            self.spent_by_work_order[work_order_id] = (
                self.spent_by_work_order.get(work_order_id, 0) + tokens
            )
        if self.total_spent > self.max_budget:
            raise TokenBudgetExceeded(
                f"Orçamento global excedido: {self.total_spent}/{self.max_budget} tokens."
            )

    def check_work_order_budget(self, work_order_id: str, limit: int) -> bool:
        return self.spent_by_work_order.get(work_order_id, 0) <= limit

    def summary(self) -> dict[str, object]:
        return {
            "max_budget": self.max_budget,
            "total_spent": self.total_spent,
            "remaining": self.remaining,
            "by_role": dict(self.spent_by_role),
            "by_work_order": dict(self.spent_by_work_order),
        }


def compact_text(text: str, max_chars: int = 600) -> str:
    """
    Trunca logs ou saídas extensas preservando início e fim (onde geralmente
    estão a causa raiz e a exceção final), evitando desperdício de contexto.
    """
    cleaned = text.strip()
    if len(cleaned) <= max_chars:
        return cleaned
    head = max_chars // 2 - 20
    tail = max_chars - head - 30
    omitted = len(cleaned) - head - tail
    return f"{cleaned[:head]}\n... [{omitted} chars omitidos] ...\n{cleaned[-tail:]}"
