"""
Definição das três camadas hierárquicas de agentes do framework VERITAS:
  1. CoordinatorAgent (Agente Coordenador / Chief of Staff)
  2. ProjectManagerAgent (Gerente de Projetos por Domínio)
  3. ExecutorAgent (Agente Executor Especialista)

Cada camada tem escopo de contexto estritamente delimitado para maximizar
confiabilidade estrutural e economia de tokens a longo prazo.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from framework.feature_map import FeatureMap
from framework.schemas import (
    ApprovalStatus,
    EvidenceBundle,
    ExecutionPatch,
    Objective,
    TaskReport,
    WorkOrder,
)


class ExecutorAgent(ABC):
    """
    Agente Executor (Specialist Worker).

    Recebe apenas:
      - WorkOrder delimitada (context_slice + allowed_files)
      - Feedback compacto da tentativa anterior (se houver)
    Nunca recebe o repositório inteiro nem histórico de outras WorkOrders.
    """

    def __init__(self, name: str, domain: str) -> None:
        self.name = name
        self.domain = domain

    @abstractmethod
    def execute(
        self,
        work_order: WorkOrder,
        attempt: int,
        previous_feedback: str | None = None,
    ) -> ExecutionPatch:
        """Gera um ExecutionPatch para a WorkOrder."""


class ProjectManagerAgent:
    """
    Gerente de Projetos (Domain Lead / PM).

    Responsabilidades:
      - Quebrar funcionalidades do seu domínio em WorkOrders atômicas.
      - Definir critérios de aceite, arquivos permitidos e probes reais a partir do Feature Map.
      - Aprovar, rejeitar para auto-correção ou escalar com base APENAS no EvidenceBundle.
    """

    def __init__(self, domain: str, feature_map: FeatureMap) -> None:
        self.domain = domain
        self.feature_map = feature_map

    def plan_work_orders(
        self,
        objective: Objective,
        feature_keys: list[str],
        per_order_budget: int,
    ) -> list[WorkOrder]:
        orders: list[WorkOrder] = []
        for idx, feature_key in enumerate(feature_keys, start=1):
            entry = self.feature_map.get(feature_key)
            if entry.domain != self.domain:
                raise ValueError(
                    f"PM do domínio '{self.domain}' recebeu feature '{feature_key}' do domínio '{entry.domain}'."
                )
            orders.append(
                WorkOrder(
                    work_order_id=f"{objective.objective_id}-{self.domain}-{idx:02d}",
                    objective_id=objective.objective_id,
                    domain=self.domain,
                    feature_key=feature_key,
                    summary=f"[{self.domain}] {objective.title} :: {entry.description}",
                    allowed_files=entry.files,
                    acceptance_criteria=entry.invariants,
                    probes=entry.probes,
                    token_budget=per_order_budget,
                    context_slice=self.feature_map.build_context_slice(feature_key),
                )
            )
        return orders

    def review_evidence(
        self,
        work_order: WorkOrder,
        evidence: EvidenceBundle,
        attempt: int,
        budget_remaining_for_order: bool,
    ) -> ApprovalStatus:
        """
        Aprovação baseada em evidência (Evidence-Based Approval).
        Nenhuma revisão manual de código bruto: se os 3 gates (incluindo runtime real)
        passaram, aprova; caso contrário, solicita retry ou escala.
        """
        if evidence.passed:
            return ApprovalStatus.APPROVED
        if attempt < work_order.max_retries and budget_remaining_for_order:
            return ApprovalStatus.REJECTED_RETRYABLE
        return ApprovalStatus.ESCALATED


class CoordinatorAgent:
    """
    Agente Coordenador (Chief of Staff).

    Responsabilidades:
      - Receber objetivos de alto nível.
      - Agrupar features por domínio via Feature Map e delegar aos PMs.
      - Distribuir orçamento global de tokens.
      - Consolidar relatórios finais sem jamais ler código-fonte bruto.
    """

    def __init__(self, feature_map: FeatureMap) -> None:
        self.feature_map = feature_map

    def route_by_domain(self, objective: Objective) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for feature_key in objective.target_features:
            entry = self.feature_map.get(feature_key)
            grouped.setdefault(entry.domain, []).append(feature_key)
        return grouped

    def allocate_work_order_budget(self, objective: Objective, total_orders: int) -> int:
        # Reserva 15% do orçamento para coordenação/planejamento e divide o restante
        execution_pool = int(objective.max_token_budget * 0.85)
        return max(500, execution_pool // max(1, total_orders))

    def summarize_mission(
        self,
        objective: Objective,
        reports: list[TaskReport],
        ledger_summary: dict[str, object],
    ) -> dict[str, object]:
        approved = [r for r in reports if r.status == ApprovalStatus.APPROVED]
        escalated = [r for r in reports if r.status == ApprovalStatus.ESCALATED]
        return {
            "objective_id": objective.objective_id,
            "title": objective.title,
            "mission_passed": len(escalated) == 0 and len(approved) == len(reports),
            "approved_count": len(approved),
            "escalated_count": len(escalated),
            "token_ledger": ledger_summary,
            "reports": [
                {
                    "work_order_id": r.work_order_id,
                    "domain": r.domain,
                    "status": r.status.value,
                    "attempts": r.attempts,
                    "tokens_used": r.tokens_used,
                    "modified_files": r.modified_files,
                    "evidence": r.evidence.to_compact_dict() if r.evidence else None,
                    "escalation_reason": r.escalation_reason,
                }
                for r in reports
            ],
        }
