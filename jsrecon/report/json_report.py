"""Relatório JSON (mesmo conteúdo do --json no stdout)."""

from __future__ import annotations

import json
from pathlib import Path

from jsrecon.models import ReconResult


def to_json(result: ReconResult, reveal: bool = False) -> str:
    return json.dumps(result.to_dict(reveal), ensure_ascii=False, indent=2)


def write_json(result: ReconResult, path: Path, reveal: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(result, reveal), encoding="utf-8")
    return path
