from __future__ import annotations

from xpars import http


def test_get_basic(server):
    c = http.Client(timeout=5)
    r = c.get(server + "/")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_body_cap(server):
    c = http.Client(timeout=5, max_bytes=1000)
    r = c.get(server + "/big")
    assert len(r.content) <= 1000


def test_body_uncapped_default(server):
    c = http.Client(timeout=5)
    r = c.get(server + "/big")
    assert "AAAA" in r.text
