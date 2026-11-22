"""
Orquestrador VERITAS — Motor de execução fechada com loop de verificação real.

Fluxo completo:
  Objective
    -> CoordinatorAgent (roteia por domínio e aloca budget)
    -> ProjectManagerAgent (emite WorkOrders delimitadas pelo Feature Map)
    -> ExecutorAgent (gera ExecutionPatch com contexto mínimo)
    -> RuntimeVerifier (Gate 1 Hard Constraints -> Gate 2 Unit -> Gate 3 App Real)
    -> ProjectManagerAgent (revisa APENAS EvidenceBundle -> aprova / retry / escala)
    -> CoordinatorAgent (consolida relatório final e ledger de tokens)
"""

from __future__ import annotations

from framework.agents import CoordinatorAgent, ExecutorAgent, ProjectManagerAgent
from framework.feature_map import FeatureMap
from framework.runtime_verifier import RuntimeVerifier
from framework.schemas import ApprovalStatus, EvidenceBundle, Objective, TaskReport
from framework.token_budget import TokenBudgetExceeded, TokenLedger


class VeritasOrchestrator:
    """Coordena a execução fim-a-fim de um objetivo com validação em runtime real."""

    def __init__(
        self,
        feature_map: FeatureMap,
        verifier: RuntimeVerifier,
        executors_by_domain: dict[str, ExecutorAgent],
    ) -> None:
        self.feature_map = feature_map
        self.verifier = verifier
        self.coordinator = CoordinatorAgent(feature_map)
        self.project_managers: dict[str, ProjectManagerAgent] = {
            domain: ProjectManagerAgent(domain, feature_map)
            for domain in feature_map.list_domains()
        }
        self.executors_by_domain = executors_by_domain

    def run(self, objective: Objective) -> dict[str, object]:
        ledger = TokenLedger(max_budget=objective.max_token_budget)
        # Custo fixo mínimo de roteamento do Coordenador (somente Feature Map, sem código bruto)
        ledger.record("coordinator", 120)

        grouped = self.coordinator.route_by_domain(objective)
        total_orders = sum(len(keys) for keys in grouped.values())
        per_order_budget = self.coordinator.allocate_work_order_budget(objective, total_orders)

        reports: list[TaskReport] = []

        for domain, feature_keys in grouped.items():
            pm = self.project_managers[domain]
            executor = self.executors_by_domain.get(domain)
            if executor is None:
                raise KeyError(f"Nenhum ExecutorAgent registrado para o domínio '{domain}'.")

            # Custo compacto de planejamento do PM
            ledger.record(f"pm:{domain}", 100)
            work_orders = pm.plan_work_orders(objective, feature_keys, per_order_budget)

            for work_order in work_orders:
                reports.append(self._execute_work_order(pm, executor, work_order, ledger))

        return self.coordinator.summarize_mission(objective, reports, ledger.summary())

    def _execute_work_order(
        self,
        pm: ProjectManagerAgent,
        executor: ExecutorAgent,
        work_order,
        ledger: TokenLedger,
    ) -> TaskReport:
        feedback: str | None = None
        last_evidence: EvidenceBundle | None = None
        last_files: list[str] = []

        for attempt in range(1, work_order.max_retries + 1):
            try:
                patch = executor.execute(
                    work_order=work_order,
                    attempt=attempt,
                    previous_feedback=feedback,
                )
                ledger.record(
                    role=f"executor:{executor.name}",
                    tokens=patch.tokens_used,
                    work_order_id=work_order.work_order_id,
                )
            except TokenBudgetExceeded as exc:
                return TaskReport(
                    work_order_id=work_order.work_order_id,
                    domain=work_order.domain,
                    status=ApprovalStatus.ESCALATED,
                    attempts=attempt,
                    tokens_used=ledger.spent_by_work_order.get(work_order.work_order_id, 0),
                    evidence=last_evidence,
                    modified_files=last_files,
                    escalation_reason=str(exc),
                )

            last_files = sorted(patch.modified_files.keys())

            # Verificação determinística + runtime real (custo = 0 tokens de LLM)
            evidence = self.verifier.verify_patch(work_order, patch)
            last_evidence = evidence

            # Revisão do PM baseada exclusivamente no EvidenceBundle compacto
            try:
                ledger.record(f"pm:{work_order.domain}", 60, work_order.work_order_id)
            except TokenBudgetExceeded as exc:
                return TaskReport(
                    work_order_id=work_order.work_order_id,
                    domain=work_order.domain,
                    status=ApprovalStatus.ESCALATED,
                    attempts=attempt,
                    tokens_used=ledger.spent_by_work_order.get(work_order.work_order_id, 0),
                    evidence=evidence,
                    modified_files=last_files,
                    escalation_reason=str(exc),
                )

            budget_ok = ledger.check_work_order_budget(
                work_order.work_order_id, work_order.token_budget
            )
            decision = pm.review_evidence(work_order, evidence, attempt, budget_ok)

            if decision == ApprovalStatus.APPROVED:
                return TaskReport(
                    work_order_id=work_order.work_order_id,
                    domain=work_order.domain,
                    status=ApprovalStatus.APPROVED,
                    attempts=attempt,
                    tokens_used=ledger.spent_by_work_order.get(work_order.work_order_id, 0),
                    evidence=evidence,
                    modified_files=last_files,
                )

            if decision == ApprovalStatus.ESCALATED:
                reason = (
                    "Orçamento de tokens da WorkOrder excedido."
                    if not budget_ok
                    else f"Máximo de tentativas ({work_order.max_retries}) atingido sem aprovação em runtime."
                )
                return TaskReport(
                    work_order_id=work_order.work_order_id,
                    domain=work_order.domain,
                    status=ApprovalStatus.ESCALATED,
                    attempts=attempt,
                    tokens_used=ledger.spent_by_work_order.get(work_order.work_order_id, 0),
                    evidence=evidence,
                    modified_files=last_files,
                    escalation_reason=reason,
                )

            # Retry: envia APENAS o feedback compacto da falha de volta ao Executor
            feedback = evidence.compact_feedback

        return TaskReport(
            work_order_id=work_order.work_order_id,
            domain=work_order.domain,
            status=ApprovalStatus.ESCALATED,
            attempts=work_order.max_retries,
            tokens_used=ledger.spent_by_work_order.get(work_order.work_order_id, 0),
            evidence=last_evidence,
            modified_files=last_files,
            escalation_reason="Loop encerrado sem aprovação.",
        )
