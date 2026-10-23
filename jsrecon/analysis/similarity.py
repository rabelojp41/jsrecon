"""Comparação entre a resposta via CDN e a resposta direta do IP candidato."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher

import httpx

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
WEIGHTS = {"status": 0.2, "title": 0.3, "length": 0.15, "html": 0.35}
MAX_TOKENS = 3000


@dataclass
class Fingerprint:
    status: int
    title: str
    length: int
    body: str

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("body")
        return d


def fingerprint(resp: httpx.Response) -> Fingerprint:
    body = resp.text
    m = TITLE_RE.search(body)
    title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    return Fingerprint(resp.status_code, title, len(resp.content), body)


def _tokens(html: str) -> list[str]:
    """Tokens no nível de tag — robusto para HTML minificado em uma linha só."""
    return [t.strip() for t in re.split(r"(?<=>)", html) if t.strip()][:MAX_TOKENS]


def html_similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    return SequenceMatcher(None, ta, tb, autojunk=False).ratio()


def compare(reference: Fingerprint, candidate: Fingerprint) -> tuple[float, dict[str, float]]:
    parts = {
        "status": 1.0 if reference.status == candidate.status else 0.0,
        "title": 1.0 if reference.title and reference.title == candidate.title else
                 (0.5 if not reference.title and not candidate.title else 0.0),
        "length": (min(reference.length, candidate.length) / max(reference.length, candidate.length))
                  if max(reference.length, candidate.length) else 1.0,
        "html": html_similarity(reference.body, candidate.body),
    }
    score = sum(WEIGHTS[k] * v for k, v in parts.items())
    return round(score, 3), {k: round(v, 3) for k, v in parts.items()}


def verdict(score: float) -> str:
    if score >= 0.75:
        return "provável origem (validado)"
    if score >= 0.45:
        return "inconclusivo (validado)"
    return "não corresponde (validado)"
