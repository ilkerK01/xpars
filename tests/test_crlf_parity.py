from xpars import crlf


def test_new_contexts_present():
    ctx = {v[0] for v in crlf.vectors("abc")}
    for c in ("crlf-xfo", "crlf-cors", "crlf-location", "crlf-sessionfix",
              "crlf-cache", "crlf-logpoison", "crlf-smuggling"):
        assert c in ctx


def test_all_vectors_raw_crlf():
    assert all(v[1].startswith("\r\n") for v in crlf.vectors("abc"))


def test_evaluate_xfo_canary():
    vs = {v[0]: v for v in crlf.vectors("abc")}
    ctx, val, hdr, ck = vs["crlf-xfo"]
    ev = crlf.evaluate(ctx, hdr, ck, "abc",
                       {hdr: "1", "X-Frame-Options": "ALLOWALL"}, "")
    assert ev and "header injected" in ev


def test_evaluate_sessionfix_cookie():
    vs = {v[0]: v for v in crlf.vectors("abc")}
    ctx, val, hdr, ck = vs["crlf-sessionfix"]
    ev = crlf.evaluate(ctx, hdr, ck, "abc",
                       {"Set-Cookie": "PHPSESSID=" + ck + "; path=/"}, "")
    assert ev and "set-cookie" in ev


def test_location_vector_has_redirect_line():
    vs = {v[0]: v for v in crlf.vectors("abc")}
    assert "Location: https://xpars-abc.invalid/" in vs["crlf-location"][1]


def test_severity_map():
    assert crlf.SEVERITY["crlf-smuggling"] == "medium"
    assert crlf.SEVERITY["crlf-cache"] == "medium"
    assert crlf.SEVERITY["crlf-location"] == "high"
    assert crlf.SEVERITY["crlf-xfo"] == "high"
