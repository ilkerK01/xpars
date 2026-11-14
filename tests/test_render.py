from xpars import render, scope


def test_render_available_is_bool():
    assert isinstance(render.available(), bool)


def test_render_in_scope_strict_and_subdomains():
    sc = scope.Scope(allow=["un.org"])
    sh = {"psdata.un.org"}
    rd = {"un.org"}
    assert render._in_scope("https://psdata.un.org/x", sh, rd, "strict", sc) is True
    assert render._in_scope("https://api.psdata.un.org/x", sh, rd, "strict", sc) is False
    assert render._in_scope("https://api.psdata.un.org/x", sh, rd, "subdomains", sc) is True
    assert render._in_scope("https://evil.com/x", sh, rd, "subdomains", sc) is False


def test_render_in_scope_denylist_blocks_eu():
    sc = scope.Scope(allow=["un.org"])
    sh = {"x.un.org"}
    rd = {"un.org", "europa.eu"}
    assert render._in_scope("https://x.europa.eu/a", sh, rd, "subdomains", sc) is False


def test_render_crawl_no_seeds_empty():
    sc = scope.Scope(allow=["un.org"])
    assert render.render_crawl([], sc) == set()


def test_render_crawl_denied_seed_empty():
    sc = scope.Scope(allow=["example.org"])
    assert render.render_crawl(["https://psdata.un.org/"], sc) == set()
