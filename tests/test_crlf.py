from __future__ import annotations

from xpars import crlf, http


def test_evaluate_header_injected():
    ev = crlf.evaluate("crlf-header", "x-xpars-abc", None, "abc",
                       {"X-Xpars-abc": "1", "Content-Type": "text/html"}, "")
    assert ev and "header injected" in ev


def test_evaluate_header_absent():
    ev = crlf.evaluate("crlf-header", "x-xpars-abc", None, "abc",
                       {"Content-Type": "text/html"}, "")
    assert ev is None


def test_evaluate_setcookie():
    ev = crlf.evaluate("crlf-setcookie", None, "xpars-abc", "abc",
                       {"Set-Cookie": "xpars-abc=1; path=/"}, "")
    assert ev and "set-cookie" in ev


def test_evaluate_body_split():
    body = "<html><body>abc<svg onload=alert(1)></body></html>"
    ev = crlf.evaluate("crlf-body", None, None, "abc", {}, body)
    assert ev and "body split" in ev


def test_vectors_shape():
    vs = crlf.vectors("abc")
    assert any(v[0] == "crlf-body" for v in vs)
    assert all(v[1].startswith("\r\n") for v in vs)


def test_scan_crlf_header_live(server):
    client = http.Client(timeout=5)
    out = crlf.scan_crlf(client, server + "/crlf-hdr?x=1")
    assert any(f["context"] == "crlf-header" and f["param"] == "x" for f in out)


def test_crlf_body_no_fp_on_plain_reflection(server):
    client = http.Client(timeout=5)
    out = crlf.scan_crlf(client, server + "/crlf-body?x=1")
    assert all(f["context"] != "crlf-body" for f in out)


def test_scan_crlf_safe_live(server):
    client = http.Client(timeout=5)
    out = crlf.scan_crlf(client, server + "/safe?q=1")
    assert out == []
