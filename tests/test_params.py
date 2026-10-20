from __future__ import annotations

from xpars import params


def test_injectable():
    assert params.injectable("http://h/a?x=1&y=2") == ["x", "y"]
    assert params.injectable("http://h/a") == []


def test_set_param_replaces_only_target():
    out = params.set_param("http://h/a?x=1&y=2", "x", "PWN")
    assert "x=PWN" in out
    assert "y=2" in out


def test_add_param():
    out = params.add_param("http://h/a?x=1", "y", "2")
    assert "x=1" in out and "y=2" in out
    out2 = params.add_param("http://h/a", "q", "1")
    assert out2.endswith("?q=1")


def test_brute_candidates():
    cands = params.brute_candidates("http://h/a", ["q", "search"])
    assert "http://h/a?q=1" in cands
    assert "http://h/a?search=1" in cands
    assert len(params.brute_candidates("http://h/a")) == len(params.COMMON_PARAMS)
