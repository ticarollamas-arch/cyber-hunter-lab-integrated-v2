# Auditoria da implementação existente e linha de base (RF-008)

Data: 2026-11-25 · Commit auditado: `359f42c` (branch `main`) · Tag de recuperação: `baseline-2026-11-25`

## 1. Como restaurar o estado anterior

```bash
git checkout baseline-2026-11-25      # inspecionar o estado original
git checkout -b restaura baseline-2026-11-25   # recomeçar a partir dele
```

Todo o trabalho novo está na branch `feat/motor-de-pesquisa`. Nenhum commit foi feito em `main`.

## 2. Inventário do projeto

| Item | Situação encontrada |
|---|---|
| Stack | Next.js 15, React 19, TypeScript, JSZip, `@opencode-ai/sdk` |
| Tamanho | 39 arquivos, ~5,7 mil linhas (2.270 em `src/app/page.tsx`) |
| Rotas de API | 15 (`chat`, `workspace`, `security-audit`, `reverse-engineering`, `github/*`, `9router/*`, `models`, `providers/[id]/auth`, `skills`, `groq/verify`, `health`) |
| Testes automatizados | **Nenhum** (não há script `test` nem arquivos de teste) |
| CI | **Nenhum** workflow em `.github/` |
| Lockfile | `bun.lock` vazio (0 bytes); não há `package-lock.json` |
| `.gitignore` | **Ausente** (só existe `.vercelignore`) |

## 3. Linha de base executada neste ambiente

| Passo | Comando | Resultado | Observação |
|---|---|---|---|
| Instalação | `npm install` | **Falhou** | O ambiente de execução não tem acesso ao registro npm (erro de rede). Não é defeito do projeto. |
| Verificação de tipos | `npm run lint` (`tsc --noEmit`) | **Falhou (1.067 erros)** | Todos derivados da falta de `node_modules`: TS2307 (módulo não encontrado), TS2591 (`process`/`Buffer`), TS7026 (JSX sem tipos do React). Não é possível separar erros reais de erros de ambiente sem instalar dependências. |
| Build | `npm run build` | **Não executado** | Depende da instalação. |
| Testes | — | **Não existem** | |

Conclusão honesta: **a linha de base do app Next.js não pôde ser medida aqui**. O CI criado nesta entrega (`.github/workflows/ci.yml`) roda `npm install`, `tsc` e `next build` no GitHub, onde há rede; o primeiro resultado desse job é a linha de base real do front-end.

## 4. Achados da auditoria (não corrigidos nesta entrega)

Seguindo o RF-009, problemas sem reprodução ficam marcados como **não confirmados**. Como o app não pôde ser executado aqui, todos os itens abaixo vêm de leitura de código e estão como *hipótese* até serem reproduzidos.

| # | Arquivo | Hipótese | Impacto | Estado |
|---|---|---|---|---|
| A-01 | `api/chat`, `api/workspace`, `api/providers/[id]/auth` | `customServerUrl` vem do cliente e é usado como URL do servidor OpenCode, sem allowlist. Permite que o backend faça requisições a destinos arbitrários (SSRF, CWE-918) e envie a senha do OpenCode a eles. | Alto se o app for público | Não confirmado |
| A-02 | Todas as rotas protegidas | Se `APP_ACCESS_TOKEN` não estiver definido, nenhuma rota exige autenticação. | Alto em implantação pública | Não confirmado |
| A-03 | `src/app/page.tsx` | O front-end nunca envia o cabeçalho `x-app-token`. Se `APP_ACCESS_TOKEN` for definido, a própria interface passa a receber 401. | Funcional | Não confirmado |
| A-04 | Rotas protegidas | Comparação do token com `!==` (não é tempo constante, CWE-208). | Baixo | Não confirmado |
| A-05 | `api/security-audit`, `api/workspace` | O limite de descompactação usa `_data.uncompressedSize` (campo privado e declarado pelo próprio ZIP). Um ZIP com tamanho declarado falso pode passar do limite (zip bomb, CWE-409). | Médio | Não confirmado |
| A-06 | `package.json` | `@opencode-ai/sdk: "latest"` e lockfile vazio: builds não reproduzíveis (supply chain). | Médio | Confirmado por leitura |
| A-07 | raiz | Falta `.gitignore`: `node_modules`, `.next` e `.env.local` podem ser commitados por engano. | Médio | Confirmado por leitura → **corrigido** (único ajuste fora do motor novo, sem efeito em runtime) |

Recomendação: corrigir A-01 a A-05 numa branch própria, depois que o job de CI do front-end estiver verde, com um teste que falhe antes e passe depois de cada correção.

## 5. O que foi reaproveitado

| Existente | Reaproveitamento |
|---|---|
| Regras estáticas de `api/security-audit` (segredos, TLS desativado, execução dinâmica, CORS, debug, Docker, Kubernetes, Terraform) | Portadas para o motor de SAST em Python (`engine/chl_engine/sast/rules.py`), com o mesmo texto de recomendação e com CWE adicionado. A rota original continua intacta. |
| Lista de diretórios/arquivos sensíveis ignorados (`SKIP`) | Reusada na extração segura de ZIP do motor. |
| Integração 9Router / Groq (APIs compatíveis com OpenAI, chave só no servidor) | O orquestrador de IA do motor usa o mesmo formato `/v1/chat/completions` e as mesmas variáveis `NINEROUTER_*` / `GROQ_API_KEY`. |
| Arquitetura recomendada em `SECURITY-ROADMAP.md` (executor na VPS, Semgrep, OSV-Scanner, Gitleaks, Trivy, normalização, deduplicação, IA só para triagem) | Seguida como desenho do motor. |
| Interface (tema escuro, abas) | Nova aba **Pesquisa** adicionada sem alterar as abas existentes. |

## 6. O que não foi alterado

Chat, workspace ZIP, engenharia reversa, GitHub/ZipToGit, central de modelos, 9Router, skills, apresentação e a auditoria ZIP original seguem com o mesmo código.
