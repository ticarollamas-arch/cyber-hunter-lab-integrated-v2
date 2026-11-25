# Entrega: motor de pesquisa autorizada (fase 1)

Branch `feat/motor-de-pesquisa` · base: tag `baseline-2026-11-25`

## Decisões de arquitetura

| # | Decisão | Motivo |
|---|---|---|
| ADR-001 | Motor em Python (`engine/`) com painel próprio; o app Next.js ganha a aba **Pesquisa Bug Bounty**, que embute o painel | Pesquisas longas, ferramentas de linha de comando e limites de recurso não cabem em funções serverless de 60 s; o `SECURITY-ROADMAP.md` já previa executor na VPS. O app existente não foi reescrito. |
| ADR-002 | SQLite (WAL) em vez de PostgreSQL | Uma VPS, sem serviço extra; o ambiente de desenvolvimento não tinha driver PostgreSQL. Acesso concentrado em `db.py` para facilitar a troca. |
| ADR-003 | Flask em vez de FastAPI | Upload multipart sem dependências extras; o ambiente não permitia instalar pacotes. |
| ADR-004 | Scanners ativos de terceiros (nuclei, ZAP) fora desta fase | Enviam tráfego próprio e contornariam escopo e limite de taxa. Exigem proxy de imposição de escopo. |
| ADR-005 | IA sem ferramentas e com saída validada | Elimina a classe de ataque "injeção dispara ação" em vez de tentar filtrá-la. |

## Rastreabilidade

| Requisito | Implementação | Teste | Situação |
|---|---|---|---|
| RF-001 Escopo autorizado | `scope.py`, `http.py`, `jobs.create` | T-001, e2e | Implementado e testado |
| RF-002 Análise estática | `sast/` | T-002 | Implementado e testado (Python por AST; JS por regras de linha) |
| RF-003 Estados dos achados | `findings.py` | T-003 | Implementado e testado |
| RF-004 Relatório | `reports.py` | T-004, test_api | Implementado e testado (revisão humana do conteúdo continua necessária) |
| RF-005 Modelo no servidor | `ai.py` | T-005 | Implementado e testado com provedor simulado; **não testado com provedor real** |
| RF-006 RAG | — | — | **Pendente** (não pedido no objetivo ajustado) |
| RF-007 Prompt injection | `ai.py` | T-007 | Implementado e testado |
| RF-008 Linha de base | `01-auditoria-e-linha-de-base.md`, tag | T-008 (conferência manual) | Feito; build do Next.js não medível aqui |
| RF-009 Causa raiz | — | — | Achados A-01..A-05 registrados como não confirmados |
| RF-010 Sem regressão | Mudanças no app Next.js restritas a uma aba nova e `.gitignore` | CI `web` | **A confirmar no CI** |
| RF-011 Deduplicação | `findings.py` | T-011 | Implementado e testado |
| RF-012 Auditoria | `audit.py` | T-012, e2e | Implementado e testado |
| RF-013 Custo | `ai.py` | T-013 | Implementado e testado |
| RF-014 Avaliação contínua da IA | — | — | **Pendente** |
| RNF-001 Taxa | `RateLimiter` | T-001 | Implementado e testado |
| RNF-002 Isolamento | `zipsafe.py`, `tools.run` | T-002 | Implementado; limites de CPU/memória só para ferramentas externas |
| RNF-004 Latência/streaming | — | — | **Pendente** (triagem não usa streaming) |

## Evidências de funcionamento (`docs/evidencias/`)

Pesquisa real contra o laboratório local (`engine/lab/vulnapp.py`), conduzida pelo painel:

- `01-escopo-do-programa.png` — escopo versionado, exclusão de `/admin/`, regras.
- `02-aguardando-aprovacao.png` — pesquisa pausada; plano de 9 testes ativos aguardando confirmação.
- `03-pesquisa-concluida-hipoteses.png` — etapas, ferramentas (Semgrep/Gitleaks marcados como indisponíveis), 10 hipóteses.
- `04-ativos-e-superficie.png`, `05-evidencias-http.png`, `06-trilha-de-auditoria.png`.
- `relatorio-exemplo.md|pdf|sarif` — relatório com o único achado validado manualmente (XSS refletido).

Números dessa execução: 31 requisições a 5 req/s, 0 acessos ao caminho excluído `/admin/painel` (conferido no log do laboratório), 2 links externos registrados sem requisição, cadeia de auditoria íntegra.

## Limitações conhecidas

- DNS rebinding: o escopo resolve o host antes de cada requisição, mas a conexão não é fixada no IP verificado.
- DAST ativo cobre apenas parâmetros GET (formulários POST ficam para revisão manual).
- Taint Python é intraprocedural (não segue chamadas entre funções/arquivos).
- Clonagem de repositório Git ainda não existe; o código entra por ZIP.
- Correlação CVE de tecnologias detectadas no site só para bibliotecas JS conhecidas (jQuery, Bootstrap, AngularJS, Lodash).
- A correção dos achados A-01..A-05 do app Next.js não foi feita nesta entrega.
