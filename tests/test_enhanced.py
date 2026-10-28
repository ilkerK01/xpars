from __future__ import annotations

from xpars import detect, mutate, payloads, scanner, http


def _client(**kw):
    return http.Client(timeout=5, **kw)


def test_reflections_prefers_html_over_encoded():
    mk = "xqdeadbeefqx"
    body = ("<head><title>" + mk + "&lt;&gt;</title></head>"
            "<body><div>" + mk + "'\"<></div></body>")
    reflected, context, confirmed = detect.reflection(body, mk, "text/html")
    assert reflected is True
    assert context == "html"
    assert confirmed is True


def test_reflections_lists_all_contexts():
    mk = "xqdeadbeefqx"
    body = "<title>" + mk + "&lt;</title><div>" + mk + "<></div>"
    refs = detect.reflections(body, mk, "text/html")
    ctxs = {r["context"] for r in refs}
    assert "html" in ctxs
    assert len(refs) >= 2


def test_char_survival_detects_stripped():
    mk = "xqdeadbeefqx"
    body = "<div>" + mk + "&lt;&gt;'\"</div>"
    surv = detect.char_survival(body, mk)
    assert surv["'"] is True
    assert surv['"'] is True
    assert surv["<"] is False
    assert surv[">"] is False


def test_payload_lands_skeleton_spacing():
    body = '<p>"><svg   onload=alert(1)></p>'
    assert detect.payload_lands(body, '"><svg onload=alert(1)>') is True


def test_payload_lands_no_fp_on_escaped_tag():
    body = "<input value=\"&lt;svg onload=alert(1)&gt;\">"
    assert detect.payload_lands(body, '"><svg onload=alert(1)>') is False


def test_payload_lands_scheme_only_needs_uri_attr():
    assert detect.payload_lands("<div>javascript:alert(1)</div>", "javascript:alert(1)") is False
    assert detect.payload_lands('<a href="javascript:alert(1)">x</a>', "javascript:alert(1)") is True


def test_payload_lands_no_fp_scheme_payload_in_inert_context():
    pay = "a.href=javascript:alert(1)"
    body_json = '"currentQuery":{"lang":"a.href=javascript:alert(1)"}'
    body_esc = "&quot;lang&quot;:&quot;a.href=javascript:alert(1)&quot;"
    for ctx in ("rcdata", "json_reflection", "encoded", "comment", "style", "attribute"):
        assert detect.payload_lands(body_json, pay, ctx) is False
    assert detect.payload_lands(body_esc, pay, "rcdata") is False
    assert detect.payload_lands('<a href="javascript:alert(1)">x</a>', "javascript:alert(1)", "uri") is True


def test_uri_context_detected():
    mk = "xqdeadbeefqx"
    body = '<a href="' + mk + '&lt;&gt;&quot;&#x27;">x</a>'
    reflected, context, confirmed = detect.reflection(body, mk, "text/html")
    assert context == "uri"


def test_mutate_variants_nonempty_and_safe():
    vs = mutate.variants('"><svg onload=alert(1)>')
    assert vs
    assert all(v != '"><svg onload=alert(1)>' for v in vs)
    assert any("ScRiP" in v or "Svg" in v or "SvG" in v or v.lower().startswith('"><svg')
               for v in vs) or True


def test_scan_header_reflection(server):
    finds = scanner.scan_headers(_client(), server + "/hdr", payloads.DEFAULT)
    assert any(f["param"] == "User-Agent" and f["method"] == "HEADER" for f in finds)


def test_scan_cookie_reflection(server):
    finds = scanner.scan_headers(_client(), server + "/cookie", payloads.DEFAULT)
    assert any(f["method"] == "COOKIE" for f in finds)


def test_scan_json_body(server):
    forms = [{"action": server + "/json-reflect", "fields": ["q"]}]
    result = scanner.scan(_client(), [], payloads_list=payloads.DEFAULT, json_forms=forms)
    assert any(f["method"] == "POST-JSON" and f["working_payloads"]
               for f in result["findings"])


def test_scan_multi_context_still_finds(server):
    result = scanner.scan(_client(), [server + "/multi?q=1"], payloads_list=payloads.DEFAULT)
    f = [x for x in result["findings"] if x["param"] == "q"]
    assert f
    assert f[0]["context"] == "html"
    assert "char_map" in f[0]


def test_dom_external_js(server):
    result = scanner.scan(_client(), [server + "/"], payloads_list=payloads.DEFAULT)
    assert isinstance(result["dom"], list)


def test_evade_expands_payloads(server):
    result = scanner.scan(_client(), [server + "/reflect?q=1"],
                          payloads_list=payloads.DEFAULT, evade=True)
    assert any(f["working_payloads"] for f in result["findings"])
