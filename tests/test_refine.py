from __future__ import annotations

from xpars import refine


def test_normalize_sorts_params_and_strips_fragment():
    assert refine.normalize("http://h/x?b=2&a=1#frag") == "http://h/x?a=1&b=2"


def test_normalize_default_port():
    assert refine.normalize("http://h:80/x") == "http://h/x"


def test_dedup_value_duplicates():
    out = refine.refine(["http://h/p?id=1", "http://h/p?id=2", "http://h/p?id=3"])
    assert len(out) == 1


def test_keeps_distinct_paths():
    out = refine.refine(["http://h/a?x=1", "http://h/b?x=1"])
    assert len(out) == 2


def test_keeps_distinct_numeric_paths_by_default():
    out = refine.refine(["http://h/user/1?x=1", "http://h/user/2?x=1"])
    assert len(out) == 2


def test_aggressive_collapses_numeric_paths():
    out = refine.refine(["http://h/user/1?x=1", "http://h/user/2?x=1"],
                        collapse_numbers=True)
    assert len(out) == 1


def test_drops_static():
    out = refine.refine(["http://h/a.css", "http://h/b.png", "http://h/x?q=1"])
    assert out == ["http://h/x?q=1"]


def test_keeps_real_endpoints():
    urls = ["http://h/login.php?u=1", "http://h/api/v1/users?id=1",
            "http://h/search.aspx?q=1", "http://h/data.json?cb=1"]
    out = refine.refine(urls, params_only=True)
    assert len(out) == 4


def test_params_only_filter():
    out = refine.refine(["http://h/a?q=1", "http://h/static"], params_only=True)
    assert out == ["http://h/a?q=1"]
