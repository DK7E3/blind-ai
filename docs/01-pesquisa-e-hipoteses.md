# 01 — Pesquisa de Mercado, Hipóteses Científicas e Arquitetura

Este documento registra a fundação científica e de engenharia do projeto **blind-ai** antes da implementação do código.

---

## 1. Observação e Definição do Problema

Desenvolvedores utilizam assistentes de IA de terceiros (via chat, IDE ou CLI) para acelerar tarefas de programação. Para que a IA responda bem, o desenvolvedor precisa fornecer contexto de código.

**Problema central:** Ao compartilhar contexto com provedores externos, existe risco real de exposição de:
1. **Credenciais e segredos:** chaves de API, tokens JWT, senhas de banco de dados, chaves SSH e arquivos `.env`.
2. **Topologia e arquitetura interna:** caminhos absolutos de diretórios, nomes de microsserviços, domínios privados, IPs internos e estrutura de pastas proprietária.
3. **Contexto sensível em texto livre:** comentários no código, strings de teste, logs e nomes de clientes ou regras de negócio confidenciais.

**Limite técnico reconhecido:** Quando a exigência de uma empresa é *zero* saída de qualquer lógica de código, a única solução absoluta é inferência 100% local (*on-premise*). O **blind-ai** atua no cenário em que a empresa deseja aproveitar o poder de LLMs externas de fronteira **mantendo credenciais, identificadores e estrutura proprietária retidos localmente** via sanitização e pseudonimização reversível.

---

## 2. Estado da Arte (Pesquisa de Mercado)

### Dados (Soluções existentes)
- **Plataformas Corporativas (AI DLP Enterprise):** Formal, Strac, Mintive, DAXA.ai, LangProtect. Focam em interceptação corporativa, governança de MCP (*Model Context Protocol*) e isolamento de chaves em servidor.
- **Proxies e Gateways Open-Source:**
  - *LiteLLM Proxy*: gateway compatível com OpenAI que oferece filtros por regex e integração com Microsoft Presidio (focado em PII).
  - *Kiji Privacy Proxy*: usa modelo local leve (*DistilBERT*) para mascarar e restaurar dados pessoais.
  - *Occludra* e *Philter AI Proxy*: firewalls/proxies intermediários para tráfego de LLMs.
- **CLIs Locais:**
  - *ScrubDuck*: CLI local ("AI Airlock") para limpar logs e arquivos antes de enviar a uma IA.

### Interpretação (Lacunas identificadas)
1. **Foco concentrado em PII e chaves óbvias:** Poucas ferramentas abertas tratam especificamente a **anonimização reversível de caminhos, módulos e estrutura de código** preservando a sintaxe válida para a LLM.
2. **Fricção vs. Segurança:** Regras rígidas demais geram muitos *falsos positivos* (atrapalham o dev); regras simples demais geram *falsos negativos* (vazamento real).
3. **Ausência de arquitetura unificada leve:** Ferramentas tendem a ser *apenas* proxy complexo ou *apenas* sanitizador manual, raramente compartilhando um núcleo auditável entre CLI própria e Proxy local.

---

## 3. Método Científico: Hipóteses Testáveis

Em vez de escolher tecnologias por suposição, o desenvolvimento do **blind-ai** será guiado por três hipóteses mensuráveis:

- **H1 (Baseline Determinístico):** Uma camada puramente determinística (bloqueio de arquivos proibidos + regex + entropia de Shannon + tabela de pseudonimização) consegue detectar **$\ge 95\%$** das chaves estruturadas e caminhos internos em um conjunto de testes sintético, com latência inferior a **$100\text{ ms}$** por arquivo.
- **H2 (Limite do Determinístico vs. IA Local):** A camada puramente determinística terá queda de desempenho (*falsos negativos*) em vazamentos contextuais sem padrão fixo (ex: segredos em comentários ou nomes proprietários em texto livre). Uma segunda camada opcional com **IA local leve** (NER ou SLM quantizada) reduzirá esses falsos negativos de forma mensurável, ao custo de maior latência e uso de memória.
- **H3 (Preservação de Utilidade):** A pseudonimização reversível (substituir caminhos e identificadores na ida e restaurar na volta) permite que uma LLM externa corrija bugs no código mascarado **sem quebrar a execução** após a restauração local.

---

## 4. Plano Experimental e Métricas de Avaliação

Para validar H1, H2 e H3 de forma objetiva, construiremos um **conjunto de testes sintético** (100% fictício, sem nenhum dado real de empresas) contendo:
- Arquivos com chaves falsas (padrões AWS, OpenAI, GitHub, JWT, senhas genéricas de alta entropia).
- Arquivos com caminhos internos fictícios e IPs privados.
- Arquivos de código limpo (para medir **falsos positivos** — quando o sistema acusa vazamento sem haver).
- Arquivos com vazamentos contextuais em comentários.

### Métricas principais
1. **Recall (Cobertura / Sensibilidade):** De todos os segredos reais no dataset, quantos o motor detectou? *(Métrica mais crítica para segurança — evita falsos negativos).*
2. **Precision (Precisão):** De tudo que o motor marcou como segredo, quanto era realmente segredo? *(Evita falsos positivos que irritam o desenvolvedor).*
3. **Latência (ms):** Tempo médio para sanitizar um arquivo localmente.
4. **Taxa de Restauração Íntegra (%):** O código retornado pela IA continua sintaticamente válido após a reversão dos pseudônimos pelo Cofre Local?

---

## 5. Decisões Iniciais de Arquitetura e Tecnologias

- **Linguagem:** Python 3.12 (ecossistema nativo para manipulação de texto, AST, APIs, ML/NLP e testes).
- **Distribuição:** Código fechado / proprietário (repositório privado no GitHub).
- **Layout do pacote:** `src/blind_ai/` (padrão profissional que evita importações acidentais durante testes).
- **Separação de responsabilidades:**
  - `core/`: motor independente de segurança (regras, entropia, AST, cofre de pseudonimização e futura camada experimental de IA local).
  - `cli/`: interface de terminal própria que consome o `core/`.
  - `proxy/`: servidor HTTP local (futuro, ex: FastAPI) que consome o mesmo `core/`.
- **Testes:** `pytest` para testes unitários, de regressão e execução do benchmark sintético.
