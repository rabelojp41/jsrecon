"""Entropia de Shannon e utilitários de texto para a extração."""

from __future__ import annotations

import bisect
import math
from collections import Counter


def shannon(value: str) -> float:
    """Entropia em bits por caractere."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def has_sequential_run(value: str, run: int = 6) -> bool:
    """Detecta alfabetos/tabelas embutidas (ABCDEF..., 012345...)."""
    streak = 1
    for a, b in zip(value, value[1:]):
        streak = streak + 1 if ord(b) - ord(a) == 1 else 1
        if streak >= run:
            return True
    return False


class LineIndex:
    """Converte offset de caractere em número de linha (1-based)."""

    def __init__(self, text: str):
        self._starts = [0]
        pos = text.find("\n")
        while pos != -1:
            self._starts.append(pos + 1)
            pos = text.find("\n", pos + 1)

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._starts, offset)
