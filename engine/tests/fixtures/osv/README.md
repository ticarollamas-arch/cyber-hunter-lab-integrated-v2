# Base OSV reduzida para testes

Trechos de dois registros públicos do OSV/GitHub Advisory Database, reduzidos aos campos que o motor usa
(id, aliases, severidade CVSS, faixa afetada e referências). Conferidos em 2026-11-25:

- GHSA-8q59-q68h-6hv4 (CVE-2020-14343) — PyYAML, introduzido 0, corrigido em 5.4.
- GHSA-gxr4-xjj5-5px2 (CVE-2020-11022) — jQuery (npm), introduzido 1.2.0, corrigido em 3.5.0.

Em produção use a API do OSV (`CHL_OSV_ONLINE=1`) ou baixe a base completa por ecossistema
(https://osv-vulnerabilities.storage.googleapis.com/) e aponte `CHL_OSV_OFFLINE_DIR` para ela.
