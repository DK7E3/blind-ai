"""Demonstração executável de 60 segundos do Blind AI (Roteiro de Apresentação).

Executa ao vivo as 4 etapas principais do produto em um cenário corporativo
100% fictício (varejo/fintech):
  1. Empacotamento seguro de um repositório multi-arquivo (ContextPacker + Cofre Cifrado)
  2. Prova de Zero Vazamento no contexto enviado para a LLM externa
  3. Restauração em Streaming SSE (placeholders quebrados em chunks) + Validação AST
  4. Placar Científico ao vivo (Experimento H1 vs. H2 + Benchmark Adversarial)

Uso:
  python examples/demo_professor.py
"""

from __future__ import annotations

import ast
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from blind_ai.core.adversarial_benchmark import run_adversarial_benchmark
from blind_ai.core.config import BlindAIConfig
from blind_ai.core.experiment import run_h1_vs_h2_experiment
from blind_ai.core.packer import ContextPacker
from blind_ai.core.secure_vault import load_encrypted, save_encrypted
from blind_ai.proxy.openai_gateway import StreamRestorer


def _banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def main() -> None:
    # Tokens 100% fictícios montados em runtime para demonstração
    fake_aws = "AKIA" + "99FICTITIOUSCORP"
    fake_db_pass = "SuperS3cret" + "Fictional2026!"
    fake_db_url = f"postgres://credito_app:{fake_db_pass}@10.42.18.99:5432/credito_prod"
    fake_comment_pw = "Inverno" + "Amazonas!2026"
    prop_engine = "MotorCreditoCorporativo"
    prop_score = "ScoreFidelidadeV2"

    _banner("1. CENARIO CORPORATIVO FICTICIO (MULTI-ARQUIVO + SEGREDOS + TERMOS)")
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / ".env").write_text(f"AWS_SECRET={fake_aws}\n", encoding="utf-8")
        (repo / ".blindai.toml").write_text(
            f'proprietary_terms = ["{prop_engine}", "{prop_score}"]\n',
            encoding="utf-8",
        )
        (repo / "src").mkdir()
        (repo / "src" / "config_db.py").write_text(
            f'# Senha temporaria de contingencia do banco: {fake_comment_pw}\n'
            f'AWS_KEY_ID = "{fake_aws}"\n'
            f'DATABASE_URL = "{fake_db_url}"\n'
            f'PRIMARY_NODE = "10.42.18.99"\n',
            encoding="utf-8",
        )
        (repo / "src" / "servico_credito.py").write_text(
            f'def calcular_limite(cliente_id: int) -> dict:\n'
            f'    """Consulta {prop_engine} usando {prop_score} no host 10.42.18.99."""\n'
            f'    return {{"engine": "{prop_engine}", "score": "{prop_score}", "host": "10.42.18.99"}}\n',
            encoding="utf-8",
        )

        cfg = BlindAIConfig.from_toml(repo / ".blindai.toml")
        packer = ContextPacker(config=cfg)
        result = packer.pack(repo)

        vault_file = repo / "sessao.vault"
        save_encrypted(result.vault, vault_file, passphrase="demo-passphrase-local")

        print(f"- Arquivos incluidos no contexto da IA : {result.included_files}")
        print(f"- Arquivos bloqueados pela Camada 1    : {result.blocked_files} ({result.blocked_reasons})")
        print(f"- Tokens estimados no pacote           : ~{result.estimated_tokens} tokens")
        print(f"- Entidades sensiveis pseudonimizadas  : {len(result.vault.placeholder_to_value)}")
        print(f"- Cofre salvo e cifrado em disco (0600): {vault_file.name} ({vault_file.stat().st_size} bytes)")

        _banner("2. O QUE A IA EXTERNA ENXERGA (CONTEXTO 100% SANITIZADO)")
        print(result.bundle.strip())

        for raw_secret in (fake_aws, fake_db_pass, fake_comment_pw, "10.42.18.99", prop_engine, prop_score):
            assert raw_secret not in result.bundle, f"Vazamento detectado: {raw_secret}"
        print("\n[OK] PROVA DE ZERO VAZAMENTO: Nenhum segredo, IP ou termo proprietario aparece no bundle!")

        _banner("3. RESTAURACAO EM STREAMING SSE (CHUNKS QUEBRADOS) + VALIDACAO AST")
        loaded_vault = load_encrypted(vault_file, passphrase="demo-passphrase-local")
        ip_ph = loaded_vault.value_to_placeholder["10.42.18.99"]
        eng_ph = loaded_vault.value_to_placeholder[prop_engine]

        simulated_ai_code = (
            f"def conectar_cluster() -> str:\n"
            f"    return 'Conectado ao {eng_ph} no IP {ip_ph} com timeout=5s'\n"
        )
        # Quebra a resposta da IA em pedacos de 6 caracteres (cortando os placeholders no meio!)
        chunks = [simulated_ai_code[i : i + 6] for i in range(0, len(simulated_ai_code), 6)]
        restorer = StreamRestorer(loaded_vault)
        reconstructed = "".join(restorer.feed(c) for c in chunks) + restorer.flush()

        print("Resposta da IA (antes da restauracao):")
        print("  " + simulated_ai_code.strip().replace("\n", "\n  "))
        print("\nCodigo restaurado ao vivo via StreamRestorer (chunks de 6 bytes):")
        print("  " + reconstructed.strip().replace("\n", "\n  "))
        ast.parse(reconstructed)
        print("\n[OK] Hipotese H3 validada: Codigo Python restaurado passa em ast.parse()!")

    _banner("4. PLACAR CIENTIFICO AO VIVO (H1 vs. H2 + BENCHMARK ADVERSARIAL)")
    exp = run_h1_vs_h2_experiment()
    adv = run_adversarial_benchmark()
    print(exp.format_summary())
    print(
        f"\nBenchmark Adversarial Multi-Linguagem (n={adv.total_cases} casos: Python, JS, TS, YAML, JSON, SQL, Logs):\n"
        f"  Recall    : {adv.recall * 100:.1f}%\n"
        f"  Precision : {adv.precision * 100:.1f}%\n"
        f"  FPR (UUID/Git SHA benignos): {adv.fpr * 100:.1f}%\n"
        f"  Latencia  : {adv.avg_latency_ms:.3f} ms/caso"
    )
    print("\n" + "=" * 78)
    print("  DEMONSTRACAO CONCLUIDA COM SUCESSO!")
    print("=" * 78)


if __name__ == "__main__":
    main()
