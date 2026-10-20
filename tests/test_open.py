from __future__ import annotations

import time

import pytest

from xpars import blind, http, jsontpl, payloads, scanner, verify

NEEDS_PW = pytest.mark.skipif(not verify.available(), reason="playwright yok")


def _client(**kw):
    return http.Client(timeout=5, **kw)


def test_jsontpl_leaves_and_set():
    tpl = {"a": {"b": "x"}, "c": [{"d": "y"}], "n": 1}
    lv = jsontpl.leaves(tpl)
    assert ("a", "b") in lv
    assert ("c", 0, "d") in lv
    assert ("n",) not in lv
    out = jsontpl.set_at(tpl, ("a", "b"), "Z")
    assert out["a"]["b"] == "Z"
    assert tpl["a"]["b"] == "x"


def test_nested_json_scan(server):
    tpl = {"a": {"b": "x"}, "c": 1}
    result = scanner.scan(_client(), [], payloads_list=payloads.DEFAULT,
                          json_templates=[{"action": server + "/json-nested", "template": tpl}])
    f = [x for x in result["findings"] if x["method"] == "POST-JSON" and x["param"] == "a.b"]
    assert f
    assert f[0]["working_payloads"]


def test_multipart_scan(server):
    forms = [{"action": server + "/mp-reflect", "fields": ["q"]}]
    result = scanner.scan(_client(), [], post_forms=forms, multipart=True,
                          payloads_list=payloads.DEFAULT)
    assert any(f["method"] == "POST" and f["working_payloads"] for f in result["findings"])


def test_blind_vectors_have_marker():
    vs = blind.vectors("http://cb.example", "MK123")
    assert any("MK123" in v for v in vs)
    assert any("script src" in v for v in vs)


def test_blind_listener_and_correlate():
    srv, hits = blind.start_listener("127.0.0.1:0")
    addr = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        _client().get(addr + "/MKABC")
    finally:
        time.sleep(0.2)
        srv.shutdown()
    assert any(h["marker"] == "MKABC" for h in hits)
    log = [{"marker": "MKABC", "method": "GET", "url": "u", "param": "q"},
           {"marker": "NOPE", "method": "GET", "url": "u", "param": "r"}]
    conf = blind.correlate(log, hits)
    assert len(conf) == 1 and conf[0]["marker"] == "MKABC"


def test_blind_run_injects(server):
    res = blind.run(_client(), get_targets=[server + "/reflect?q=1"],
                    listen="127.0.0.1:0", wait=0.1)
    assert res["log"]
    assert res["callback"].startswith("http://127.0.0.1:")


def test_graphql_json_scan(server):
    finds, _ = scanner.scan_graphql(_client(), server + "/graphql",
                                    "{search}", {"q": "x"}, payloads.DEFAULT)
    gf = [x for x in finds if x["method"] == "GRAPHQL" and x["param"] == "variables.q"]
    assert gf
    assert gf[0]["context"] in ("json_reflection", "encoded")
    assert gf[0]["severity"] == "medium"


def test_graphql_html_scan(server):
    finds, _ = scanner.scan_graphql(_client(), server + "/graphql-html",
                                    "{search}", {"q": "x"}, payloads.DEFAULT)
    gf = [x for x in finds if x["method"] == "GRAPHQL"]
    assert gf
    assert gf[0]["context"] == "html"
    assert gf[0]["working_payloads"]


def test_graphql_query_probe_when_no_vars(server):
    finds, _ = scanner.scan_graphql(_client(), server + "/graphql-html",
                                    "{search}", {}, payloads.DEFAULT)
    assert any(x["param"] == "query" for x in finds)


@NEEDS_PW
def test_verify_graphql_html_execution(server):
    finds, _ = scanner.scan_graphql(_client(), server + "/graphql-html",
                                    "{search}", {"q": "x"}, payloads.DEFAULT)
    res = verify.verify_findings(finds)
    assert res["verified"] >= 1
    assert any(f.get("verified") and f["method"] == "GRAPHQL" for f in finds)


@NEEDS_PW
def test_verify_graphql_json_not_executed(server):
    finds, _ = scanner.scan_graphql(_client(), server + "/graphql",
                                    "{search}", {"q": "x"}, payloads.DEFAULT)
    verify.verify_findings(finds)
    gf = [f for f in finds if f["method"] == "GRAPHQL"]
    assert gf
    assert all(not f.get("verified") for f in gf)


@NEEDS_PW
def test_verify_user_agent_execution(server):
    finds = scanner.scan_headers(_client(), server + "/hdr", payloads.DEFAULT)
    uf = [f for f in finds if f["method"] == "HEADER" and f["param"] == "User-Agent"]
    assert uf
    verify.verify_findings(finds)
    assert any(f.get("verified") for f in uf)


@NEEDS_PW
def test_verify_referer_browser_controlled(server):
    finds = scanner.scan_headers(_client(), server + "/refhdr", payloads.DEFAULT)
    rf = [f for f in finds if f["method"] == "HEADER" and f["param"] == "Referer"]
    assert rf
    verify.verify_findings(finds)
    assert all(not f.get("verified") for f in rf)
    assert any(f.get("verify_note") == "browser-controlled-header" for f in rf)


@NEEDS_PW
def test_verify_get_execution(server):
    result = scanner.scan(_client(), [server + "/reflect?q=1"], payloads_list=payloads.DEFAULT)
    res = verify.verify_findings(result["findings"])
    assert res["supported"] and res["verified"] >= 1
    assert any(f.get("verified") and f.get("severity") == "critical"
               for f in result["findings"])


@NEEDS_PW
def test_verify_baseline_fp(server):
    result = scanner.scan(_client(), [server + "/selfalert?q=1"], payloads_list=payloads.DEFAULT)
    verify.verify_findings(result["findings"])
    qf = [f for f in result["findings"] if f["param"] == "q"]
    assert qf
    assert all(not f.get("verified") for f in qf)
    assert any(f.get("verify_note") == "baseline-dialog" for f in qf)


@NEEDS_PW
def test_verify_post_execution(server):
    forms = [{"action": server + "/post-reflect", "fields": ["q"]}]
    result = scanner.scan(_client(), [], post_forms=forms, payloads_list=payloads.DEFAULT)
    assert any(f["method"] == "POST" for f in result["findings"])
    res = verify.verify_findings(result["findings"])
    assert res["verified"] >= 1


@NEEDS_PW
def test_verify_cookie_execution(server):
    finds = scanner.scan_headers(_client(), server + "/cookie", payloads.DEFAULT)
    assert any(f["method"] == "COOKIE" for f in finds)
    res = verify.verify_findings(finds)
    assert res["verified"] >= 1


@NEEDS_PW
def test_verify_header_execution(server):
    finds = scanner.scan_headers(_client(), server + "/xff", payloads.DEFAULT)
    assert any(f["method"] == "HEADER" and f["param"] == "X-Forwarded-For" for f in finds)
    res = verify.verify_findings(finds)
    assert res["verified"] >= 1


@NEEDS_PW
def test_verify_dom_name(server):
    dom = [{"url": server + "/domname", "sources": ["window.name"], "sinks": ["innerhtml"]}]
    res = verify.verify_dom(dom)
    assert res["verified"] >= 1
    assert dom[0].get("verified")


@NEEDS_PW
def test_verify_dom_hash_decode(server):
    dom = [{"url": server + "/domdecode", "sources": ["location.hash"], "sinks": ["innerhtml"]}]
    assert verify.verify_dom(dom)["verified"] >= 1


@NEEDS_PW
def test_verify_dom_eval(server):
    dom = [{"url": server + "/domeval", "sources": ["location.hash"], "sinks": ["eval("]}]
    assert verify.verify_dom(dom)["verified"] >= 1


@NEEDS_PW
def test_verify_dom_search(server):
    dom = [{"url": server + "/domsearch", "sources": ["location.search"],
            "sinks": ["document.write"]}]
    assert verify.verify_dom(dom)["verified"] >= 1


@NEEDS_PW
def test_verify_dom_message(server):
    dom = [{"url": server + "/dommsg", "sources": ["postmessage"], "sinks": ["innerhtml"]}]
    assert verify.verify_dom(dom)["verified"] >= 1


@NEEDS_PW
def test_verify_dom_plain_hash_not_verified(server):
    dom = [{"url": server + "/dom", "sources": ["location.hash"], "sinks": ["innerhtml"]}]
    verify.verify_dom(dom)
    assert dom[0].get("verified") is not True
