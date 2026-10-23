"""Configuração de execução e chaves de API (lidas do ambiente)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from jsrecon import __version__
from jsrecon.models import Mode
from jsrecon.scope import Scope

DEFAULT_USER_AGENT = f"jsrecon/{__version__} (+authorized security testing)"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "jsrecon"


@dataclass(frozen=True)
class ApiKeys:
    securitytrails: str | None = None
    shodan: str | None = None
    virustotal: str | None = None

    ENV = {
        "securitytrails": "SECURITYTRAILS_API_KEY",
        "shodan": "SHODAN_API_KEY",
        "virustotal": "VIRUSTOTAL_API_KEY",
    }

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "ApiKeys":
        env = os.environ if env is None else env
        return cls(**{name: (env.get(var) or "").strip() or None for name, var in cls.ENV.items()})

    def secret_values(self) -> list[str]:
        return [v for v in (self.securitytrails, self.shodan, self.virustotal) if v]


@dataclass
class Settings:
    target: str
    scope: Scope
    mode: Mode = Mode.PASSIVE
    rate_limit: float = 5.0  # req/s contra o alvo
    passive_rate_limit: float = 2.0  # req/s contra fontes públicas (Wayback etc.)
    concurrency: int = 10
    user_agent: str = DEFAULT_USER_AGENT
    timeout: float = 15.0
    retries: int = 2
    backoff: float = 1.0  # segundos; dobra a cada tentativa
    cache_dir: Path | None = DEFAULT_CACHE_DIR  # None desliga o cache
    keys: ApiKeys = field(default_factory=ApiKeys)
    reveal: bool = False
    probe: bool = False
    probe_limit: int = 200
    wayback: bool = True
    max_historical: int = 300
    max_js: int = 300
    max_js_bytes: int = 10 * 1024 * 1024
    origin_ips: list[str] = field(default_factory=list)  # IPs fornecidos pelo usuário
    cve_intel: bool = True  # enriquece CVEs potenciais com CVSS/EPSS/KEV
    max_cves: int = 100

    @property
    def active(self) -> bool:
        return self.mode is Mode.ACTIVE
