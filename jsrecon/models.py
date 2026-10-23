"""Estruturas de dados compartilhadas entre módulos e relatórios."""

from __future__ import annotations

import hashlib
from functools import cached_property
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Mode(str, Enum):
    PASSIVE = "passivo"
    ACTIVE = "ativo"


class Status(str, Enum):
    COM_ACHADOS = "COM ACHADOS"
    SEM_ACHADOS = "SEM ACHADOS"
    PULADO = "PULADO"
    FALHA_PARCIAL = "FALHA PARCIAL"
    FALHA = "FALHA"


class Confidence(str, Enum):
    ALTA = "alta"
    MEDIA = "média"
    BAIXA = "baixa"

    @property
    def rank(self) -> int:
        return {"alta": 3, "média": 2, "baixa": 1}[self.value]


class Origin(str, Enum):
    ATUAL = "atual"
    HISTORICO = "histórico"


@dataclass
class JSFile:
    url: str
    content: str = field(repr=False)
    origin: Origin
    source: str  # page | inline | import | preload | sourcemap | wayback
    parent: str | None = None
    timestamp: str | None = None  # Wayback (YYYYMMDDhhmmss)
    digest: str | None = None  # digest do Wayback, quando houver

    @cached_property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8", "replace")).hexdigest()

    @property
    def label(self) -> str:
        """Identificação usada em arquivo:linha (inclui a data da captura se histórico)."""
        return f"{self.url}@{self.timestamp}" if self.timestamp else self.url

    @property
    def host_url(self) -> str:
        """URL "real" do arquivo (sem o sufixo de inline/sourcemap)."""
        return self.url.split("#inline-", 1)[0].split("::", 1)[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "label": self.label,
            "origin": self.origin.value,
            "source": self.source,
            "parent": self.parent,
            "timestamp": self.timestamp,
            "size": len(self.content),
            "sha256": self.sha256,
        }


@dataclass
class Location:
    file: str
    line: int
    origin: Origin

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class Endpoint:
    value: str
    method: str  # GET, POST... ou "?" quando não é possível inferir
    kind: str  # absoluta | relativa | api | graphql | graphql-op
    locations: list[Location] = field(default_factory=list)
    in_scope: bool | None = None  # só faz sentido para URLs absolutas
    probe_status: int | None = None
    probe_note: str | None = None

    @property
    def only_historical(self) -> bool:
        return bool(self.locations) and all(l.origin is Origin.HISTORICO for l in self.locations)

    @property
    def origin(self) -> Origin:
        return Origin.HISTORICO if self.only_historical else Origin.ATUAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "method": self.method,
            "kind": self.kind,
            "origin": self.origin.value,
            "only_historical": self.only_historical,
            "in_scope": self.in_scope,
            "probe_status": self.probe_status,
            "probe_note": self.probe_note,
            "locations": [
                {"file": l.file, "line": l.line, "origin": l.origin.value} for l in self.locations
            ],
        }


def mask_secret(value: str) -> str:
    """Mostra só os 4 primeiros e 4 últimos caracteres."""
    if len(value) <= 12:
        return value[:2] + "*" * max(len(value) - 2, 4)
    return f"{value[:4]}{'*' * min(len(value) - 8, 16)}{value[-4:]}"


@dataclass
class Secret:
    type: str
    value: str = field(repr=False)
    confidence: Confidence
    location: Location
    entropy: float
    note: str | None = None

    @property
    def masked(self) -> str:
        return mask_secret(self.value)

    def display(self, reveal: bool) -> str:
        return self.value if reveal else self.masked

    def to_dict(self, reveal: bool = False) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.display(reveal),
            "masked": not reveal,
            "confidence": self.confidence.value,
            "file": self.location.file,
            "line": self.location.line,
            "origin": self.location.origin.value,
            "entropy": round(self.entropy, 2),
            "note": self.note,
        }


@dataclass
class ProviderEvidence:
    provider: str
    evidence: list[str] = field(default_factory=list)
    strong: bool = False  # range oficial ou header característico


@dataclass
class CDNResult:
    behind_cdn: bool
    ips: list[str] = field(default_factory=list)
    providers: list[ProviderEvidence] = field(default_factory=list)

    def provider_names(self) -> list[str]:
        return [p.provider for p in self.providers]

    def to_dict(self) -> dict[str, Any]:
        return {
            "behind_cdn": self.behind_cdn,
            "ips": self.ips,
            "providers": [asdict(p) for p in self.providers],
        }


@dataclass
class OriginCandidate:
    ip: str
    sources: list[str] = field(default_factory=list)
    validated: bool = False
    score: float | None = None  # 0..1, só após validação
    verdict: str = "candidato"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostIntel:
    ip: str
    source: str  # internetdb | shodan
    org: str | None = None
    asn: str | None = None
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)  # potenciais (baseados em banner)
    hostnames: list[str] = field(default_factory=list)
    sans: list[str] = field(default_factory=list)
    is_cdn_edge: str | None = None  # nome do provedor quando o IP é borda de CDN
    role: str = "resolvido"  # resolvido | candidato-origem

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CveInfo:
    """Contexto público de uma CVE potencial (para priorizar o relatório)."""

    id: str
    ips: list[str] = field(default_factory=list)
    summary: str | None = None
    cvss: float | None = None
    cvss_version: float | None = None
    epss: float | None = None  # probabilidade de exploração em 30 dias (0..1)
    kev: bool = False  # consta no catálogo CISA KEV (exploração conhecida)
    published: str | None = None
    found: bool = True  # False = a fonte não tem dados dessa CVE

    @property
    def severity(self) -> str:
        if self.cvss is None:
            return "desconhecida"
        if self.cvss >= 9.0:
            return "crítica"
        if self.cvss >= 7.0:
            return "alta"
        if self.cvss >= 4.0:
            return "média"
        return "baixa" if self.cvss > 0 else "nenhuma"

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"

    def sort_key(self) -> tuple:
        return (not self.kev, -(self.cvss or 0.0), -(self.epss or 0.0), self.id)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity
        d["url"] = self.url
        return d


@dataclass
class Subdomain:
    host: str
    source: str
    in_scope: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    key: str
    title: str
    status: Status
    findings: int | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.key,
            "title": self.title,
            "status": self.status.value,
            "findings": self.findings,
            "note": self.note,
        }


@dataclass
class ReconResult:
    target: str
    mode: Mode
    scope: dict[str, Any]
    version: str
    started_at: str = ""
    finished_at: str = ""
    modules: list[ModuleResult] = field(default_factory=list)
    js_files: list[JSFile] = field(default_factory=list)
    js_skipped: list[dict[str, str]] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    cdn: CDNResult | None = None
    origins: list[OriginCandidate] = field(default_factory=list)
    favicon_hash: int | None = None
    hosts: list[HostIntel] = field(default_factory=list)
    cve_intel: list[CveInfo] = field(default_factory=list)
    subdomains: list[Subdomain] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requests: dict[str, Any] = field(default_factory=dict)

    def module(self, key: str) -> ModuleResult | None:
        return next((m for m in self.modules if m.key == key), None)

    def add_subdomain(self, host: str, source: str, in_scope: bool) -> bool:
        if any(s.host == host for s in self.subdomains):
            return False
        self.subdomains.append(Subdomain(host, source, in_scope))
        return True

    def to_dict(self, reveal: bool = False) -> dict[str, Any]:
        return {
            "meta": {
                "tool": "jsrecon",
                "version": self.version,
                "target": self.target,
                "mode": self.mode.value,
                "scope": self.scope,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "secrets_revealed": reveal,
            },
            "summary": [m.to_dict() for m in self.modules],
            "js_files": [f.to_dict() for f in self.js_files],
            "js_skipped": self.js_skipped,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "secrets": [s.to_dict(reveal) for s in self.secrets],
            "resolved_ips": self.resolved_ips,
            "cdn_waf": self.cdn.to_dict() if self.cdn else None,
            "origin_candidates": [o.to_dict() for o in self.origins],
            "favicon_mmh3": self.favicon_hash,
            "shodan": [h.to_dict() for h in self.hosts],
            "cve_intel": [c.to_dict() for c in self.cve_intel],
            "subdomains": [s.to_dict() for s in self.subdomains],
            "warnings": self.warnings,
            "requests": self.requests,
        }
