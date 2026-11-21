# blind-ai

> Motor híbrido de segurança e privacidade (CLI + Proxy/Gateway local) para desenvolvimento assistido por IA de terceiros sem vazamento de credenciais, arquitetura interna ou dados sensíveis.

## Problema

Engenheiros de software precisam enviar contexto de código para modelos de linguagem externos (LLMs) para depurar, refatorar e desenvolver mais rápido. Porém, esse fluxo cria riscos críticos de **vazamento de dados corporativos**:

- Chaves de API, tokens, senhas e arquivos `.env`.
- Caminhos internos de diretórios, nomes de servidores e endereços IP privados.
- Nomes de módulos proprietários, regras de negócio e dados sensíveis em comentários ou logs.

## Visão da Arquitetura

O `blind-ai` adota uma arquitetura modular de **Defesa em Profundidade**, onde um único núcleo de segurança (`core`) atende tanto uma **CLI própria** quanto um **Proxy/Gateway HTTP local**:

```mermaid
flowchart TD
    Dev[Desenvolvedor] --> CLI[CLI Própria]
    IDE[IDE / Outras Ferramentas] --> Proxy[Proxy / Gateway HTTP Local]

    CLI --> Core
    Proxy --> Core

    subgraph Core [Motor de Segurança Local]
        C1[Camada 1: Filtro de Arquivos Proibidos]
        C2[Camada 2: Scanner Determinístico - Regex + Entropia + AST]
        C3[Camada 3: IA Local Leve - Experimental]
        Vault[(Cofre Local de Pseudonimização)]
        C1 --> C2 --> C3
        C2 <--> Vault
        C3 <--> Vault
    end

    Core -->|Contexto Sanitizado| LLM[Provedor de IA Externo]
    LLM -->|Resposta Anonimizada| Restore[Restaurador via Cofre Local]
    Vault --> Restore
    Restore --> Dev
```

## Estrutura do Projeto

```text
blind-ai/
├── docs/
│   └── 01-pesquisa-e-hipoteses.md   # Pesquisa de mercado, método científico e métricas
├── src/
│   └── blind_ai/                    # Código-fonte do motor (Core, CLI e Proxy)
├── tests/                           # Testes automatizados e dataset sintético
├── .gitignore
└── README.md
```

## Status Atual

- [x] Fase 0: Pesquisa de mercado, definição do problema, hipóteses científicas e estrutura inicial.
- [ ] Fase 1: Dataset sintético de avaliação (*benchmark*) e Camada 1/2 (Scanner determinístico + Cofre local).
- [ ] Fase 2: CLI própria (`blind-ai scan` / `blind-ai run`).
- [ ] Fase 3: Experimento científico — Código determinístico vs. IA local leve (SLM/NER).
- [ ] Fase 4: Proxy/Gateway HTTP local e integração ponta a ponta.

## Documentação

- [01 — Pesquisa de Mercado, Hipóteses e Plano Experimental](docs/01-pesquisa-e-hipoteses.md)
