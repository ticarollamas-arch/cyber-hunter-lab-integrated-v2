"""Calculadora CVSS v3.1 (pontuação base), conforme a especificação do FIRST.

O vetor que o motor atribui a cada achado é uma *sugestão* inicial; a especificação do processo
exige revisão humana do vetor antes do relatório.
"""
from __future__ import annotations

import math

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    pass


def roundup(value: float) -> float:
    """Arredondamento para cima com uma casa, como definido no Apêndice A da especificação 3.1."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    text = vector.strip()
    if not text.startswith("CVSS:3.1/"):
        raise CvssError("o vetor deve começar com CVSS:3.1/")
    metrics: dict[str, str] = {}
    for part in text.split("/")[1:]:
        if ":" not in part:
            raise CvssError(f"métrica inválida: {part}")
        k, v = part.split(":", 1)
        if k in metrics:
            raise CvssError(f"métrica repetida: {k}")
        metrics[k] = v
    for k in _REQUIRED:
        if k not in metrics:
            raise CvssError(f"métrica obrigatória ausente: {k}")
    if metrics["S"] not in ("U", "C"):
        raise CvssError("S deve ser U ou C")
    for k in ("AV", "AC", "UI", "C", "I", "A"):
        if metrics[k] not in _W[k]:
            raise CvssError(f"valor inválido para {k}: {metrics[k]}")
    if metrics["PR"] not in _PR["U"]:
        raise CvssError(f"valor inválido para PR: {metrics['PR']}")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def severity(score: float | None) -> str:
    if score is None:
        return "info"
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
