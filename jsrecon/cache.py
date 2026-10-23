"""Cache em disco (JSON) com TTL por entrada."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class DiskCache:
    def __init__(self, root: Path | None):
        self.root = Path(root) if root else None

    @property
    def enabled(self) -> bool:
        return self.root is not None

    def _path(self, namespace: str, key: str) -> Path:
        assert self.root is not None
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.root / namespace / f"{digest}.json"

    def get(self, namespace: str, key: str, ttl: float, *, allow_stale: bool = False) -> Any | None:
        if not self.enabled:
            return None
        path = self._path(namespace, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not allow_stale and time.time() - entry.get("ts", 0) > ttl:
            return None
        return entry.get("value")

    def set(self, namespace: str, key: str, value: Any) -> None:
        if not self.enabled:
            return
        path = self._path(namespace, key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"ts": time.time(), "key": key, "value": value}), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass  # cache é best-effort
