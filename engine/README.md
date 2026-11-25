# Motor de pesquisa autorizada — CyberHuntLab

Motor em Python que executa pesquisas de vulnerabilidade em programas de Bug Bounty **autorizados**, com painel próprio para acompanhar tudo. Você informa a URL do alvo, cadastra o escopo do programa e acompanha cada etapa: ferramentas usadas, requisições enviadas e bloqueadas, hipóteses, achados validados e relatórios.

> Use somente em ativos que o programa autoriza. O motor bloqueia o que estiver fora do escopo, mas a responsabilidade pelo cadastro correto do escopo e pela aprovação dos testes ativos é de quem pesquisa.

## Fluxo de uma pesquisa

| Etapa | O que faz | Ferramenta |
|---|---|---|
| 1. Escopo | Confere o alvo contra a versão atual do escopo; fora dele, nada roda | `chl-scope` |
| 2. Reconhecimento | `robots.txt`, `sitemap.xml`, `security.txt`, rastreamento limitado, formulários, links | `chl-crawler` |
| 3. Inventário | Hosts/IPs, pontos de entrada, tecnologias e versões (cabeçalhos, cookies, scripts, `meta generator`) | `chl-fingerprint` |
| 4. Web/API (passivo) | HSTS, CSP, clickjacking, cookies, CORS (com `Origin` arbitrária), erros, listagem de diretório, OpenAPI/Swagger | `chl-webchecks` |
| 5. SAST | Fluxo fonte→sink em Python (AST), regras portadas da auditoria ZIP original, regras JS; Semgrep e Gitleaks quando instalados | `chl-pytaint`, `chl-rules` |
| 6. SCA + CVE | Manifestos (`requirements*.txt`, `package.json`, `package-lock.json`) e bibliotecas detectadas no site, correlacionados no OSV | `chl-sca` |
| 7. DAST ativo | XSS refletido, SQL injection por erro e open redirect com marcadores inofensivos — **só depois da sua aprovação** | `chl-dast` |
| 8. IA | Triagem (prioridade, chance de falso positivo, próximo passo) sobre resultados reais | `chl-ai` |
| 9. Consolidação | Duplicatas prováveis e sinais de falso positivo | — |

Cada achado tem estado (`observação → hipótese → validado | falso positivo`), histórico, CWE, caso de teste WSTG (forma versionada, ex. `WSTG-v42-INPV-01`), vetor CVSS 3.1 sugerido e evidências. **Só você valida**, e só achados validados entram no relatório (Markdown, PDF, JSON e SARIF).

## Controles obrigatórios

- **Escopo**: negação por padrão; exclusões vencem inclusões; `*.exemplo.com` não inclui `exemplo.com`; portas fora de 80/443 só se listadas; IPs só se listados; destinos que resolvem para rede privada são bloqueados (exceto laboratório). Redirecionamentos são seguidos um a um, com nova checagem. Cada alteração de escopo gera versão com hash.
- **Limite de requisições**: taxa por programa (padrão 1 req/s) e orçamento por pesquisa (padrão 500).
- **Interrupção**: botão no painel; nenhuma requisição sai depois do pedido.
- **Aprovação humana**: testes com payload pedem aprovação com confirmação explícita e só ficam disponíveis se o escopo marcar `active_testing_allowed`.
- **Cabeçalhos exigidos pelo programa** (ex. `X-Bug-Bounty`) vão em todas as requisições.
- **Auditoria**: registro somente-inclusão com cadeia de hash (`/api/audit/verify`); cada requisição fica em `http_evidence` com a regra de escopo aplicada.
- **Isolamento da análise de código**: ZIP extraído sem confiar no tamanho declarado, sem links simbólicos e sem caminhos fora do diretório; o código nunca é executado; ferramentas externas rodam sem shell, com tempo, CPU e memória limitados.
- **IA**: chave só no servidor; sem ferramentas; dados do alvo delimitados como não confiáveis; resposta validada (IDs inexistentes e campos extras são descartados); cota diária por usuário e global; provedor fora do ar gera aviso, nunca resposta inventada.
- **Ferramentas de terceiros que geram tráfego próprio** (nuclei, ZAP) não estão integradas de propósito: elas contornariam o escopo e o limite de taxa. A integração segura exige um proxy que imponha esses controles (pendente).

## Instalação

Requisitos: Python 3.11+.

```bash
cd engine
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m chl_engine.cli create-user --name carol --role admin   # mostra o token uma vez
python -m chl_engine.cli serve --host 127.0.0.1 --port 8787      # painel em http://127.0.0.1:8787
```

Em produção na VPS, rode com `gunicorn -w 1 --threads 8 "chl_engine.api:create_app()" -b 127.0.0.1:8787` e publique por HTTPS (Cloudflare Tunnel ou Nginx). Use **um** processo: as pesquisas rodam em threads desse processo.

Ferramentas opcionais detectadas automaticamente: `semgrep`, `gitleaks`, `subfinder`, `osv-scanner`. As ausentes aparecem como "indisponível" no painel.

### Variáveis de ambiente

| Variável | Uso | Padrão |
|---|---|---|
| `CHL_DATA_DIR` | banco SQLite e arquivos das pesquisas | `engine/data` |
| `CHL_AI_BASE_URL`, `CHL_AI_API_KEY`, `CHL_AI_MODEL` | provedor compatível com `/v1/chat/completions` (aceita também `NINEROUTER_*`) | vazio = IA desativada |
| `CHL_AI_DAILY_TOKENS_PER_USER` / `CHL_AI_DAILY_TOKENS_GLOBAL` / `CHL_AI_MAX_TOKENS_REQUEST` | controle de custo | 60.000 / 300.000 / 1.500 |
| `CHL_OSV_ONLINE` | consultar `api.osv.dev` | `1` |
| `CHL_OSV_OFFLINE_DIR` | base OSV local (JSON) quando não há rede | vazio |
| `CHL_FRAME_ANCESTORS` | domínio(s) HTTPS do app Next.js que podem embutir o painel | vazio |
| `CHL_USER_AGENT` | identificação nas requisições | `CyberHuntLab-Research/0.1 …` |
| `CHL_MAX_ZIP_BYTES` | tamanho máximo do ZIP de código | 200 MB |

## Laboratório local

`lab/vulnapp.py` é uma aplicação **deliberadamente vulnerável** (só em 127.0.0.1) usada nos testes, com uma versão corrigida (`--safe`) para medir falsos positivos.

```bash
python -m chl_engine.cli lab --port 8081
```

No painel, crie um programa com escopo `127.0.0.1:8081`, exclusão `http://127.0.0.1:8081/admin/`, marque "Permitir rede privada" e "permite testes ativos", e inicie a pesquisa em `http://127.0.0.1:8081/`.

## Testes

```bash
cd engine && python -m pytest -q -p no:logging tests
```

| Teste | Requisito |
|---|---|
| `test_t001_scope.py` | RF-001, RNF-001: ativo excluído recebe zero requisições, redirecionamento para fora é barrado, taxa, orçamento, método, interrupção |
| `test_t002_sast.py` | RF-002, AM-002: todas as falhas conhecidas apontadas, amostras seguras sem alerta alto, código nunca executado, zip slip, symlink, zip bomb |
| `test_t003_t004_t011_findings.py` | RF-003, RF-004, RF-011 e CVSS: estados, só pessoas validam, relatório só com validados e campos obrigatórios, deduplicação |
| `test_t005_t007_t013_ai.py` | RF-005, RF-007, RF-013: provedor fora/timeout, injeção sem ação, ID inventado descartado, chave no servidor, cotas |
| `test_t012_audit.py` | RF-012: cadeia íntegra, UPDATE/DELETE bloqueados, adulteração detectada |
| `test_sca.py` | correlação OSV, versões corrigidas, ausência de fonte informada |
| `test_e2e_lab.py` | pesquisa completa contra o laboratório, aprovação/recusa, interrupção, app corrigido sem hipóteses |
| `test_api.py` | autenticação, autorização por objeto, confirmação obrigatória, fluxo HTTP completo até o PDF |

## API (resumo)

Autenticação: `Authorization: Bearer <token>`.

| Método | Caminho | Descrição |
|---|---|---|
| GET/POST | `/api/programs` | listar / criar programa (com escopo opcional) |
| GET/PUT | `/api/programs/{id}/scope` | histórico / nova versão do escopo |
| POST | `/api/programs/{id}/scope/check` | testar URL contra o escopo (sem requisição) |
| POST | `/api/jobs` | iniciar pesquisa (`program_id`, `target`, `active`, `ai`, `repository`, `source`.zip) |
| GET | `/api/jobs/{id}` | status, etapas, aprovações, contadores |
| POST | `/api/jobs/{id}/cancel` | interromper |
| POST | `/api/approvals/{id}` | `{approve, confirm: true, reason}` |
| GET | `/api/jobs/{id}/findings` · `/assets` · `/evidence` · `/audit` | resultados |
| PATCH | `/api/findings/{id}` | vetor CVSS, impacto, passos, descrição |
| POST | `/api/findings/{id}/transition` | `{to, note}` |
| GET | `/api/jobs/{id}/report?format=md\|pdf\|json\|sarif` | relatório (só validados) |
| GET | `/api/ai/usage` · `/api/tools` · `/api/audit/verify` | consumo de IA, ferramentas, integridade |
