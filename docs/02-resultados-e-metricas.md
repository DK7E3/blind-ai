# 02 — Resultados Experimentais, Latência, Segurança e Economia de Tokens

Este documento registra as evidências quantitativas obtidas na validação das hipóteses científicas (**H1**, **H2** e **H3**) definidas em [01 — Pesquisa de Mercado, Hipóteses e Plano Experimental](01-pesquisa-e-hipoteses.md), além dos benchmarks em código real e mecanismos de economia de tokens.

---

## 1. Validação das Hipóteses Científicas (H1, H2 e H3)

### 1.1. Hipótese H1 — Baseline Determinístico (`DeterministicScanner`)
- **Critério de sucesso definido na Fase 0:** Detectar $\ge 95\%$ das chaves estruturadas e caminhos internos no dataset sintético com latência média $< 100\text{ ms}$ por arquivo.
- **Resultado alcançado:**
  - **Recall (segredos estruturados):** **$100,0\%$ (`1.0000`)** — cobrindo chaves AWS (`AKIA...`), OpenAI (`sk-proj-...`), Anthropic (`sk-ant-...`), Google (`AIza...`), Stripe (`sk_live_...` / `rk_live_...`), Slack (`xox[baprs]-...`), GitHub (`ghp_...`), JWT (`eyJ...`), blocos PEM inline (`-----BEGIN ... PRIVATE KEY-----`), credenciais em URLs (`postgres://` e `https://user:pass@`), Bearer tokens, IPs privados RFC 1918 e caminhos internos Unix/Windows.
  - **Precision:** **$100,0\%$ (`1.0000`)** (`FP = 0`).
  - **Latência média:** **$0,17\text{ ms}$ a $0,32\text{ ms}$ por caso** (cerca de **300x mais rápido** que o teto de $100\text{ ms}$).
  - **Status:** **H1 Confirmada.**

### 1.2. Hipótese H2 — Limite do Determinístico vs. Camada Contextual (`HybridScanner`)
- **Critério de sucesso definido na Fase 0:** Demonstrar que a camada puramente determinística sofre queda de *Recall* em vazamentos contextuais sem padrão fixo (comentários em código e texto livre) e que a adição da Camada 3 (`ContextualDetector`) reduz esses falsos negativos de forma mensurável.
- **Resultado do Experimento Controlado (`python -m blind_ai.core.experiment`):**

| Detector | TP | FP | FN | TN | Recall | Precision | Latência Média |
| :--- | :-: | :-: | :-: | :-: | :---: | :---: | :---: |
| **H1 (`DeterministicScanner`)** | 6 | 0 | 3 | 3 | `0.6667` (66,7%) | `1.0000` (100,0%) | `0.320 ms` |
| **H2 (`HybridScanner`: C2 + C3)** | 9 | 0 | 0 | 3 | **`1.0000` (100,0%)** | **`1.0000` (100,0%)** | **`0.423 ms`** |
| **Delta ($\text{H2} - \text{H1}$)** | **+3** | **0** | **-3** | **0** | **`+0.3333` (+33,3%)** | **`+0.0000`** | **`+0.103 ms`** |

- **Conclusão:** A camada contextual bilíngue (português e inglês) eliminou 100% dos falsos negativos em comentários com custo adicional de latência de apenas **$\sim 0,10\text{ ms}$**.
- **Status:** **H2 Confirmada.**

### 1.3. Hipótese H3 — Preservação de Utilidade e Integridade Sintática (`PseudonymVault`)
- **Critério de sucesso definido na Fase 0:** Código mascarado enviado a uma LLM externa e restaurado localmente pelo Cofre Local deve manter $100\%$ de fidelidade e continuar sintaticamente válido e executável.
- **Resultado alcançado:**
  - **Taxa de Restauração Íntegra:** **$100,0\%$** em round-trip exato (`restore(sanitize(text)) == text`), inclusive quando os placeholders (`__BLIND_<KIND>_<SEQ>__`) chegam fragmentados em múltiplos pacotes de rede SSE de 2 a 6 bytes via `StreamRestorer`.
  - **Validação AST e Execução E2E:** $100\%$ dos scripts Python sanitizados e restaurados passam em `ast.parse()` e executam sem erro no teste ponta a ponta (`tests/test_e2e_workflow.py`).
  - **Status:** **H3 Confirmada.**

---

## 2. Benchmark Adversarial Multi-Linguagem e Teste em Código Real

Para garantir que os resultados não sofrem de *overfitting* ao dataset inicial, o motor foi submetido a duas avaliações independentes:

### 2.1. Benchmark Adversarial Multi-Linguagem (`adversarial_benchmark.py`)
- **Composição:** 20 casos cobrindo **7 linguagens/formatos** (Python, JavaScript, TypeScript, YAML, JSON, SQL e Logs), incluindo strings de alta entropia **benignas** (UUIDv4, hashes Git SHA-1 e SHA-256, MIME types e expressões regulares).
- **Métricas obtidas:**
  - **Recall:** `100.0%`
  - **Precision:** `100.0%`
  - **False Positive Rate (FPR) em UUIDs/Git SHAs:** `0.0%`
  - **Latência média:** `0.470 ms/caso`

### 2.2. Auditoria Empírica na Biblioteca Padrão do Python (81 Arquivos Reais)
Varredura do `HybridScanner` sobre **81 arquivos reais** da stdlib do Python 3.12 (`json`, `email`, `http`, `urllib`, `logging`, `asyncio`):
- **Falsos positivos de `high_entropy_token`:** **`0`** (o filtro AST distingue variáveis sensíveis de nomes de classes `CamelCase`, cabeçalhos MIME `;charset=utf-8`, tabelas hexadecimais sequenciais e expressões regulares).
- **Falsos positivos de `private_ip` em loopback/versões:** **`0`** (`127.0.0.1`, `0.0.0.0` e strings de versão `0.x.y.z` são ignorados; apenas IPs privados corporativos RFC 1918 são marcados).
- **Falsos positivos de `sensitive_comment`:** **`0`**.

---

## 3. Engenharia de Economia de Tokens (`ContextPacker`)

Quando um desenvolvedor envia um repositório inteiro como contexto para uma LLM (`blind-ai pack`), o custo em tokens e o risco de estourar a janela de contexto são controlados por 4 mecanismos determinísticos:

1. **Eliminação de Arquivos de Alto Volume e Baixo Valor (Camada 1):**
   - Bloqueia automaticamente `.git/`, `.venv/`, `node_modules/`, `__pycache__/`, arquivos binários e lockfiles/arquivos minificados (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, `*.min.js`, `*.min.css`).
   - Em projetos web/Python típicos, apenas essa filtragem evita o envio de **50.000 a 300.000+ tokens inúteis** por prompt.
2. **Compressão de Segredos Longos em Placeholders Curtos:**
   - Uma chave privada RSA PEM (`~1.700` caracteres $\approx 425$ tokens) ou um token JWT longo é substituído por um único placeholder curto (`__BLIND_PEM_PRIVATE_KEY_001__`, $\sim 7$ tokens), economizando tokens na ida e na geração da resposta da LLM, já que a restauração ocorre localmente em **$0$ tokens de LLM**.
3. **Orçamento de Tokens em Tempo Linear $O(N)$ (`--max-tokens`):**
   - O `ContextPacker` mantém contadores incrementais de caracteres (`running_section_chars` e `running_tree_chars`) com custo $O(1)$ por arquivo, permitindo limitar o pacote exatamente ao orçamento desejado (ex.: `blind-ai pack . --max-tokens 120000`) sem recomputar o bundle a cada arquivo.
4. **Teto por Arquivo (`--max-file-bytes`):**
   - Bloqueia dumps SQL/JSON acidentais maiores que `1 MB` (configurável), protegendo tanto a latência local quanto o consumo de tokens na API.

---

## 4. Reproduzindo Todas as Métricas no Terminal

Qualquer pessoa pode reproduzir os números acima localmente em menos de 15 segundos:

```bash
# 1. Benchmark sintético H1 (JSON ou texto)
python -m blind_ai benchmark

# 2. Suíte completa de 144 testes (H1, H2, H3, E2E e Auditoria de Segurança V1-V6)
PYTHONPATH=src python -m unittest discover -s tests -v
```
