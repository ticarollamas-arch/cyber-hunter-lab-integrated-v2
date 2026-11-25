"""CyberHuntLab — motor de pesquisa de vulnerabilidades para programas de Bug Bounty autorizados.

Princípios que o código segue:
- Nada sai para a rede sem passar pelo escopo do programa (scope.py + http.py).
- Testes potencialmente invasivos só rodam depois de aprovação humana registrada.
- A IA interpreta resultados reais; ela não cria achados e não chama ferramentas.
- Só achados validados por uma pessoa entram em relatório.
"""

__version__ = "0.1.0"
