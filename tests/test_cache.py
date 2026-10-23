import time

from jsrecon.cache import DiskCache


def test_roundtrip_and_ttl(tmp_path, monkeypatch):
    c = DiskCache(tmp_path)
    c.set("ns", "k", {"a": 1})
    assert c.get("ns", "k", ttl=60) == {"a": 1}
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 120)
    assert c.get("ns", "k", ttl=60) is None
    assert c.get("ns", "k", ttl=60, allow_stale=True) == {"a": 1}


def test_disabled():
    c = DiskCache(None)
    c.set("ns", "k", 1)
    assert c.get("ns", "k", ttl=60) is None
