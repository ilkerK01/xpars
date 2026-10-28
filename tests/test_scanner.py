from __future__ import annotations

from xpars import http, scanner


def _client():
    return http.Client(timeout=5)


def test_reflect_flagged(server):
    result = scanner.scan(_client(), [server + "/reflect?q=1"], threads=2)
    assert any(f["context"] == "html" and f["param"] == "q" for f in result["findings"])


def test_safe_not_flagged(server):
    result = scanner.scan(_client(), [server + "/safe?q=1"], threads=2)
    assert result["findings"] == []


def test_attribute_flagged(server):
    result = scanner.scan(_client(), [server + "/attr?x=1"], threads=2)
    assert any(f["context"] == "attribute" for f in result["findings"])


def test_dom_flagged(server):
    result = scanner.scan(_client(), [server + "/dom"], threads=2)
    assert any("location.hash" in d["sources"] for d in result["dom"])


def test_blind_sent(server):
    result = scanner.scan(_client(), [server + "/reflect?q=1"], threads=2,
                          blind='"><script src=//x.oast/></script>')
    assert any(b["param"] == "q" for b in result["blind_sent"])


def test_payload_confirmation(server):
    from xpars import payloads
    result = scanner.scan(_client(), [server + "/reflect?q=1"], threads=2,
                          payloads_list=payloads.DEFAULT)
    finding = [f for f in result["findings"] if f["param"] == "q"][0]
    assert any("svg" in p for p in finding["working_payloads"])


def test_safe_no_working_payload(server):
    from xpars import payloads
    result = scanner.scan(_client(), [server + "/safe?q=1"], threads=2,
                          payloads_list=payloads.DEFAULT)
    assert result["findings"] == []


def test_waf_payload_block_then_evade(server):
    from xpars import payloads
    result = scanner.scan(_client(), [server + "/wafparam?q=1"], threads=2,
                          payloads_list=payloads.DEFAULT)
    fs = [f for f in result["findings"] if f["param"] == "q"]
    assert fs and fs[0].get("working_payloads")
    assert fs[0].get("waf") == "payload-blocked"


def test_waf_full_block_skipped(server):
    result = scanner.scan(_client(), [server + "/wafblock?q=1"], threads=2)
    assert all(f["param"] != "q" for f in result["findings"])


def test_waf_post_evade(server):
    from xpars import payloads
    result = scanner.scan(_client(), [], threads=2, payloads_list=payloads.DEFAULT,
                          post_forms=[{"action": server + "/wafpost", "fields": ["q"]}])
    fs = [f for f in result["findings"] if f["param"] == "q"]
    assert fs and fs[0].get("working_payloads")


def test_csrf_value_preserved(server):
    from xpars import payloads
    result = scanner.scan(_client(), [], threads=2, payloads_list=payloads.DEFAULT,
                          post_forms=[{"action": server + "/csrfpost",
                                       "fields": ["q", "token"],
                                       "values": {"token": "s3cr3t"}}])
    assert any(f["param"] == "q" for f in result["findings"])


def test_csrf_missing_value_not_flagged(server):
    from xpars import payloads
    result = scanner.scan(_client(), [], threads=2, payloads_list=payloads.DEFAULT,
                          post_forms=[{"action": server + "/csrfpost",
                                       "fields": ["q", "token"]}])
    assert all(f["param"] != "q" for f in result["findings"])


def test_dom_cross_block(server):
    result = scanner.scan(_client(), [server + "/domsplit"], threads=2)
    assert any("location.hash" in d["sources"] and "innerhtml" in d["sinks"]
               for d in result["dom"])


def test_dom_inline_handler(server):
    result = scanner.scan(_client(), [server + "/dominline"], threads=2)
    assert any(d.get("how") == "dom-inline" and "location.hash" in d["sources"]
               for d in result["dom"])


def test_dom_taint_linked(server):
    result = scanner.scan(_client(), [server + "/domtaint"], threads=2)
    assert any(d.get("how") == "dom-taint-linked" for d in result["dom"])


def test_dom_cookie_source(server):
    result = scanner.scan(_client(), [server + "/domcookie"], threads=2)
    assert any("document.cookie" in d["sources"] for d in result["dom"])


def test_dom_storage_source(server):
    result = scanner.scan(_client(), [server + "/domstorage"], threads=2)
    assert any("localstorage" in d["sources"] for d in result["dom"])


def test_prefilter_skips_4xx(server):
    result = scanner.scan(_client(), [server + "/wafblock?q=1"], threads=2,
                          prefilter=True)
    assert result["findings"] == []
    assert result["interrupted"] is False


def test_prefilter_off_scans_normally(server):
    result = scanner.scan(_client(), [server + "/reflect?q=1"], threads=2,
                          prefilter=False)
    assert any(f["param"] == "q" for f in result["findings"])


def test_on_update_fires_on_finding(server):
    hits = {"n": 0, "last": 0}

    def cb(res):
        hits["n"] += 1
        hits["last"] = len(res["findings"])

    scanner.scan(_client(), [server + "/reflect?q=1"], threads=2, on_update=cb)
    assert hits["n"] >= 1
    assert hits["last"] >= 1
