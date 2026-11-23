"""
Contratos de dados tipados para comunicação entre agentes.

Princípio de Economia de Tokens:
Nenhum agente envia arquivos inteiros ou logs brutos para camadas superiores.
Toda comunicação trafega apenas contratos estruturados e EvidenceBundles compactos.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED_RETRYABLE = "rejected_retryable"
    ESCALATED = "escalated"


@dataclass(frozen=True)
class ProbeSpec:
    """Define uma verificação real contra a aplicação em execução."""

    name: str
    method: str = "GET"
    path: str = "/health"
    expected_status: int = 200
    expected_json_subset: dict[str, Any] = field(default_factory=dict)
    expected_body_contains: str | None = None
    payload: dict[str, Any] | None = None
    timeout_seconds: float = 5.0


@dataclass(frozen=True)
class Objective:
    """Objetivo de alto nível recebido pelo Agente Coordenador."""

    objective_id: str
    title: str
    description: str
    target_features: list[str]
    max_token_budget: int = 12_000


@dataclass
class WorkOrder:
    """Ordem de serviço delimitada emitida por um Gerente de Projeto para um Executor."""

    work_order_id: str
    objective_id: str
    domain: str
    feature_key: str
    summary: str
    allowed_files: list[str]
    acceptance_criteria: list[str]
    probes: list[ProbeSpec]
    max_retries: int = 3
    token_budget: int = 3_000
    context_slice: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionPatch:
    """Saída de um Agente Executor: alterações propostas em arquivos permitidos."""

    work_order_id: str
    attempt: int
    modified_files: dict[str, str]  # caminho relativo -> novo conteúdo
    rationale: str
    tokens_used: int = 0


@dataclass(frozen=True)
class ConstraintViolation:
    """Violação determinística detectada sem gastar tokens de LLM."""

    rule_id: str
    file_path: str
    message: str
    line: int | None = None


@dataclass
class GateResult:
    """Resultado individual de cada camada de verificação."""

    gate_name: str
    passed: bool
    duration_ms: int
    summary: str
    details: list[str] = field(default_factory=list)


@dataclass
class EvidenceBundle:
    """
    Prova estruturada de execução (Proof-of-Execution).
    É o ÚNICO artefato de verificação enviado ao PM e ao Coordenador.
    """

    work_order_id: str
    attempt: int
    passed: bool
    gates: list[GateResult]
    runtime_artifacts: dict[str, Any] = field(default_factory=dict)
    compact_feedback: str = ""

    def to_compact_dict(self) -> dict[str, Any]:
        """Serialização mínima para consumo de agentes superiores com baixo custo de tokens."""
        return {
            "work_order_id": self.work_order_id,
            "attempt": self.attempt,
            "passed": self.passed,
            "gates": [
                {
                    "gate": g.gate_name,
                    "ok": g.passed,
                    "ms": g.duration_ms,
                    "summary": g.summary,
                }
                for g in self.gates
            ],
            "feedback": self.compact_feedback,
        }


@dataclass
class TaskReport:
    """Relatório final consolidado de uma WorkOrder para o Coordenador."""

    work_order_id: str
    domain: str
    status: ApprovalStatus
    attempts: int
    tokens_used: int
    evidence: EvidenceBundle | None
    modified_files: list[str] = field(default_factory=list)
    escalation_reason: str | None = None
