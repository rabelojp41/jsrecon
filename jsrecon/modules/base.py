"""Contrato comum dos módulos."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from jsrecon.cache import DiskCache
from jsrecon.config import ApiKeys, Settings
from jsrecon.dns import Resolver
from jsrecon.http import HttpClient, OutOfScopeError
from jsrecon.models import ModuleResult, ReconResult, Status
from jsrecon.ui import UI


@dataclass
class Context:
    settings: Settings
    http: HttpClient
    dns: Resolver
    cache: DiskCache
    ui: UI
    result: ReconResult
    shared: dict[str, Any] = field(default_factory=dict)

    async def baseline(self) -> httpx.Response | None:
        """Resposta da página inicial do alvo (via CDN), buscada uma única vez. Só no modo ativo."""
        if "baseline" not in self.shared:
            self.shared["baseline"] = None
            if self.settings.active:
                for scheme in ("https", "http"):
                    try:
                        self.shared["baseline"] = await self.http.get(
                            f"{scheme}://{self.settings.target}/", max_bytes=self.settings.max_js_bytes
                        )
                        break
                    except (httpx.HTTPError, OutOfScopeError) as exc:
                        self.shared.setdefault("baseline_errors", []).append(f"{scheme}: {type(exc).__name__}")
        return self.shared["baseline"]


class Module(ABC):
    key: str = ""
    title: str = ""
    requires_active: bool = False
    requires_keys: tuple[str, ...] = ()  # nomes de campos de ApiKeys — todos obrigatórios

    def skip_reason(self, ctx: Context) -> str | None:
        if self.requires_active and not ctx.settings.active:
            return "requer --active"
        missing = [ApiKeys.ENV[k] for k in self.requires_keys if not getattr(ctx.settings.keys, k)]
        if missing:
            return f"{', '.join(missing)} ausente"
        return None

    @abstractmethod
    async def run(self, ctx: Context) -> ModuleResult: ...

    def done(self, findings: int, note: str = "", *, partial: bool = False) -> ModuleResult:
        if partial:
            status = Status.FALHA_PARCIAL
        else:
            status = Status.COM_ACHADOS if findings else Status.SEM_ACHADOS
        return ModuleResult(self.key, self.title, status, findings, note)

    def skipped(self, note: str) -> ModuleResult:
        return ModuleResult(self.key, self.title, Status.PULADO, None, note)

    def failed(self, note: str) -> ModuleResult:
        return ModuleResult(self.key, self.title, Status.FALHA, None, note)
