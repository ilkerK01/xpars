from __future__ import annotations

from xpars import http, payloads, scanner


def _scan(server, path):
    client = http.Client(timeout=5)
    return scanner.scan(client, [server + path], threads=2,
                        payloads_list=payloads.DEFAULT)


def _ctx(result, param="q"):
    return {f["context"] for f in result["findings"] if f["param"] == param}


def test_comment_context(server):
    assert "comment" in _ctx(_scan(server, "/comment?q=1"))


def test_textarea_rcdata(server):
    assert "rcdata" in _ctx(_scan(server, "/textarea?q=1"))


def test_title_rcdata(server):
    assert "rcdata" in _ctx(_scan(server, "/title?q=1"))


def test_style_context(server):
    assert "style" in _ctx(_scan(server, "/style?q=1"))


def test_single_quote_attribute(server):
    assert "attribute" in _ctx(_scan(server, "/sqattr?q=1"))


def test_single_quote_script(server):
    assert "script" in _ctx(_scan(server, "/sqscript?q=1"))


def test_href_js_attribute(server):
    assert "attribute" in _ctx(_scan(server, "/hrefjs?q=1"))


def test_escaped_attribute_no_fp(server):
    assert _scan(server, "/escattr?q=1")["findings"] == []


def test_waf_block_no_fp(server):
    assert _scan(server, "/wafblock?q=1")["findings"] == []


def test_simple_html_still_caught(server):
    assert "html" in _ctx(_scan(server, "/reflect?q=1"))


def test_simple_safe_still_clean(server):
    assert _scan(server, "/safe?q=1")["findings"] == []


def test_textarea_not_mislabeled_html(server):
    ctx = _ctx(_scan(server, "/textarea?q=1"))
    assert "html" not in ctx
