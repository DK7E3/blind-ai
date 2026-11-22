"""
Feature Map — Mapa semântico determinístico da aplicação.

Inspirado na abordagem da Lauren Tan na SpaceX:
Em vez de cada agente queimar milhares de tokens explorando o repositório
e adivinhando rotas, arquivos e invariantes, o Feature Map fornece uma
fatia mínima e exata de contexto por funcionalidade.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from framework.schemas import ProbeSpec


@dataclass(frozen=True)
class FeatureEntry:
    key: str
    domain: str
    description: str
    files: list[str]
    invariants: list[str]
    probes: list[ProbeSpec]
    unit_test_command: list[str]


class FeatureMap:
    """Resolve funcionalidades para arquivos permitidos, invariantes e probes reais."""

    def __init__(self, app_entrypoint: list[str], health_path: str, features: dict[str, FeatureEntry]):
        self.app_entrypoint = app_entrypoint
        self.health_path = health_path
        self._features = features

    @classmethod
    def from_file(cls, path: Path) -> FeatureMap:
        raw = json.loads(path.read_text(encoding="utf-8"))
        features: dict[str, FeatureEntry] = {}
        for key, item in raw["features"].items():
            probes = [
                ProbeSpec(
                    name=p["name"],
                    method=p.get("method", "GET"),
                    path=p["path"],
                    expected_status=p.get("expected_status", 200),
                    expected_json_subset=p.get("expected_json_subset", {}),
                    expected_body_contains=p.get("expected_body_contains"),
                    payload=p.get("payload"),
                    timeout_seconds=p.get("timeout_seconds", 5.0),
                )
                for p in item.get("probes", [])
            ]
            features[key] = FeatureEntry(
                key=key,
                domain=item["domain"],
                description=item["description"],
                files=list(item["files"]),
                invariants=list(item.get("invariants", [])),
                probes=probes,
                unit_test_command=list(item.get("unit_test_command", [])),
            )
        return cls(
            app_entrypoint=list(raw["runtime"]["entrypoint"]),
            health_path=raw["runtime"].get("health_path", "/health"),
            features=features,
        )

    def get(self, feature_key: str) -> FeatureEntry:
        if feature_key not in self._features:
            available = ", ".join(sorted(self._features))
            raise KeyError(f"Feature '{feature_key}' não encontrada no Feature Map. Disponíveis: {available}")
        return self._features[feature_key]

    def list_domains(self) -> list[str]:
        return sorted({f.domain for f in self._features.values()})

    def build_context_slice(self, feature_key: str) -> dict[str, Any]:
        """Retorna apenas os metadados mínimos que o Executor precisa (economia de tokens)."""
        entry = self.get(feature_key)
        return {
            "feature": entry.key,
            "domain": entry.domain,
            "description": entry.description,
            "allowed_files": entry.files,
            "invariants": entry.invariants,
        }
