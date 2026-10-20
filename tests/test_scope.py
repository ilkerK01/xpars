from __future__ import annotations

from xpars.scope import Scope


def test_localhost_allowed():
    assert Scope().permitted("http://127.0.0.1:8000/x?q=1")


def test_default_deny_eu_unesco():
    assert not Scope().permitted("http://europa.eu/x?q=1")
    assert not Scope().permitted("http://data.europa.eu/x?q=1")
    assert not Scope().permitted("https://whc.unesco.org/x?q=1")


def test_allowlist():
    sc = Scope(allow=["example.com"])
    assert sc.permitted("http://example.com/a?x=1")
    assert not sc.permitted("http://other.com/a?x=1")


def test_exclude():
    sc = Scope(deny=["blocked.com"])
    assert not sc.permitted("http://blocked.com/a?x=1")
    assert sc.permitted("http://allowed.com/a?x=1")
