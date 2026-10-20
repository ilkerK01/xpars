from __future__ import annotations

import time

from xpars import detect, http, params, payloads, report, scanner, stored, verify


def _client(**kw):
    return http.Client(timeout=5, **kw)


def test_path_segments_and_set():
    segs = params.path_segments("http://h/a/b/c")
    idxs = [i for i, _ in segs]
    assert idxs
    u = params.set_path_segment("http://h/a/b/c", idxs[-1], "X")
    assert u.endswith("/X")


def test_scan_path_finds(server):
    finds = scanner.scan_path(_client(), server + "/pathrefl/seed",
                              payloads_list=payloads.DEFAULT)
    assert any(f["method"] == "PATH" for f in finds)
    assert any(f["working_payloads"] for f in finds)


def test_path_scan_via_scan(server):
    result = scanner.scan(_client(), [server + "/pathrefl/seed"], path_scan=True,
                          payloads_list=payloads.DEFAULT)
    assert any(f["method"] == "PATH" for f in result["findings"])


def test_stored_detection(server):
    forms = [{"action": server + "/guestbook", "fields": ["msg"]}]
    finds, sent = stored.run(_client(), [], forms, [server + "/guestbook"])
    assert sent
    assert any(f["method"] == "STORED" and f["severity"] in ("high", "critical")
               for f in finds)


def test_stored_safe_no_fp(server):
    finds, sent = stored.run(_client(), [server + "/safe?q=1"], [],
                             [server + "/safe?q=1"])
    assert sent
    assert finds == []


def test_dom_pass_hash_gets_payload(server):
    result = scanner.scan(_client(), [server + "/dom"])
    hash_doms = [d for d in result["dom"] if "location.hash" in d.get("sources", [])]
    assert hash_doms
    assert hash_doms[0].get("payload")
    assert "#" in hash_doms[0].get("poc", "")


def test_dom_pass_dedups_pages(server):
    result = scanner.scan(_client(), [server + "/dom", server + "/dom"])
    hash_doms = [d for d in result["dom"] if "location.hash" in d.get("sources", [])]
    assert len(hash_doms) == 1


def test_verify_dom_empty_safe():
    res = verify.verify_dom([])
    assert res["verified"] == 0
    assert res["candidates"] == 0


def test_verify_dom_without_playwright_unsupported():
    if verify.available():
        return
    dom = [{"url": "http://h/x", "sources": ["location.hash"], "sinks": ["innerhtml"],
            "payload": "<img src=x onerror=alert(1)>"}]
    res = verify.verify_dom(dom)
    assert res["supported"] is False
    assert res["candidates"] == 1


def test_rps_sets_interval():
    c = _client(rps=10.0)
    assert abs(c.min_interval - 0.1) < 1e-6
    assert _client().min_interval == 0.0


def test_rps_throttles(server):
    c = _client(rps=20.0)
    t0 = time.monotonic()
    c.get(server + "/")
    c.get(server + "/")
    c.get(server + "/")
    assert time.monotonic() - t0 >= 0.08


def test_report_poc_path_and_stored():
    fp = {"method": "PATH", "url": "http://h/a/b", "param": "path[2]:b",
          "payload": '"><svg onload=alert(1)>', "path_index": 2}
    assert "curl" in report.poc(fp)
    fs = {"method": "STORED", "url": "http://h/show", "param": "msg",
          "payload": '"><img src=x onerror=alert(1)>',
          "source_url": "http://h/add", "source_method": "POST"}
    out = report.poc(fs)
    assert "sonra ac" in out and "http://h/show" in out


def test_scan_csti_detects_eval(server):
    finds = scanner.scan_csti(_client(), server + "/csti?q=1")
    assert any(f["method"] == "CSTI-GET" and f["how"] == "template-eval" for f in finds)
    assert any("{{1337*1337}}" == f["payload"] for f in finds)


def test_scan_csti_no_fp_on_reflect(server):
    finds = scanner.scan_csti(_client(), server + "/reflect?q=1")
    assert finds == []


def test_csti_via_scan(server):
    result = scanner.scan(_client(), [server + "/csti?q=1"], csti=True,
                          payloads_list=payloads.DEFAULT)
    assert any(f["method"] == "CSTI-GET" for f in result["findings"])


def test_onmessage_dom_detected():
    js = "window.onmessage=function(e){document.getElementById('b').innerHTML=e.data;};"
    hits = detect.dom_findings("<script>" + js + "</script>")
    assert hits
    assert "onmessage" in hits[0]["sources"]
    assert "innerhtml" in hits[0]["sinks"]


def test_nonexec_script_type_is_rcdata():
    body = '<script type="application/json">{"q":"ZZMKZZ<>"}</script>'
    refs = detect.reflections(body, "ZZMKZZ", "text/html")
    assert refs and refs[0]["context"] == "rcdata"
    body2 = "<script>var a='ZZMKZZ';</script>"
    refs2 = detect.reflections(body2, "ZZMKZZ", "text/html")
    assert refs2 and refs2[0]["context"] == "script"


def test_payload_lands_breakout_context_strict():
    quote_only = "';alert(1)//"
    body = "prefix " + quote_only + " suffix"
    assert detect.payload_lands(body, quote_only) is True
    assert detect.payload_lands(body, quote_only, "rcdata") is False
    tagpay = "</textarea><svg onload=alert(1)>"
    body2 = "x" + tagpay + "y"
    assert detect.payload_lands(body2, tagpay, "rcdata") is True


def test_json_reflection_severity_medium(server):
    finds, _ = scanner.scan_url(_client(), server + "/jsonget?q=1",
                                payloads_list=payloads.DEFAULT)
    jf = [f for f in finds if f["context"] == "json_reflection"]
    assert jf
    assert jf[0]["severity"] == "medium"


def test_scan_dom_urls_covers_paramless(server):
    result = scanner.scan(_client(), [], dom_urls=[server + "/dom"])
    assert any("location.hash" in d.get("sources", []) for d in result["dom"])


def test_report_poc_csti_and_graphql():
    fc = {"method": "CSTI-GET", "url": "http://h/p?q=1", "param": "q",
          "payload": "{{1337*1337}}"}
    assert "curl" in report.poc(fc) and "q=" in report.poc(fc)
    fg = {"method": "GRAPHQL", "url": "http://h/graphql", "param": "variables.q",
          "payload": '"><svg onload=alert(1)>',
          "json_template": {"query": "{x}", "variables": {"q": "x"}},
          "json_path": ["variables", "q"]}
    out = report.poc(fg)
    assert "curl" in out and "application/json" in out
