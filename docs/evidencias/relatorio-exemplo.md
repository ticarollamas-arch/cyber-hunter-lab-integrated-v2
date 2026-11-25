# Relatório de segurança — Laboratório local (app vulnerável)

- Alvo: `http://127.0.0.1:8081/`
- Execução: #1 (2026-11-25T15:24:48.521962Z → 2026-11-25T15:24:57.445820Z)
- Escopo aplicado: versão 1 (sha256 `f60701f5e1a2eaf7…`)
- Gerado em: 2026-11-25T15:25:05.297747Z
- Política do programa: docs/evidencias

> Todos os achados abaixo foram validados manualmente. Evidências têm segredos e dados pessoais mascarados.

## 1. Entrada refletida sem codificação (possível XSS refletido)

| Campo | Valor |
|---|---|
| Severidade | MEDIUM — CVSS 6.1 |
| Vetor CVSS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| CWE | CWE-79 Cross-site Scripting |
| WSTG | WSTG-v42-INPV-01 |
| Local | `http://127.0.0.1:8081/search?q=PAYLOAD` |
| Ferramenta | chl-dast |

### Descrição

O parâmetro q de /search é refletido na página sem codificação de saída.

### Passos de reprodução

1. Acesse http://127.0.0.1:8081/search?q=%22%3E%3Ci%3Eteste%3C/i%3E
2. Observe que o texto aparece em itálico: a entrada é inserida no HTML sem codificação.

### Impacto

Um atacante pode executar JavaScript no navegador de quem abrir um link preparado, no contexto da aplicação.

### Evidências

- http: GET http://127.0.0.1:8081/search?q=chl0ca20369%22%3E%3Ci%3Echl0ca20369%3C%2Fi%3E → 200 em 2026-11-25T15:24:55.036852Z

```http
GET http://127.0.0.1:8081/search?q=chl0ca20369%22%3E%3Ci%3Echl0ca20369%3C%2Fi%3E
User-Agent: CyberHuntLab-Research/0.1 (+authorized bug bounty research)
```

```http
HTTP 200
server: Werkzeug/3.1.9 Python/3.13.18
date: Wed, 25 Nov 2026 15:24:55 GMT
content-type: text/html; charset=utf-8
content-length: 82
x-powered-by: LabFramework/1.2.3
connection: close

<html><body><h1>Resultados para chl0ca20369"><i>chl0ca20369</i></h1></body></html>
```

### Recomendação

Codifique a saída conforme o contexto (HTML, atributo, JS) e adote CSP.
