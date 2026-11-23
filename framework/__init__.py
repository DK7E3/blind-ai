"""
VERITAS — Multi-Agent Verification & Runtime Validation Framework.

Arquitetura hierárquica (Coordenador -> Gerentes de Projeto -> Executores)
com validação obrigatória em tempo de execução na aplicação real,
hard constraints determinísticos e economia estrutural de tokens.
"""

from framework.schemas import (
    ApprovalStatus,
    ConstraintViolation,
    EvidenceBundle,
    ExecutionPatch,
    GateResult,
    Objective,
    ProbeSpec,
    TaskReport,
    WorkOrder,
)
from framework.orchestrator import VeritasOrchestrator

__all__ = [
    "ApprovalStatus",
    "ConstraintViolation",
    "EvidenceBundle",
    "ExecutionPatch",
    "GateResult",
    "Objective",
    "ProbeSpec",
    "TaskReport",
    "WorkOrder",
    "VeritasOrchestrator",
]
