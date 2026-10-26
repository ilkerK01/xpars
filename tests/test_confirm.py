from __future__ import annotations

import pytest

from xpars import confirm, http, payloads, report, scanner

NEEDS_PW = pytest.mark.skipif(not confirm.available(), reason="playwright yok")


def _client(**kw):
    return http.Client(timeout=5, **kw)


def test_available_is_bool():
    assert isinstance(confirm.available(), bool)


def test_marker_is_js_safe_and_unique():
    a, b = confirm.new_marker(), confirm.new_marker()
    assert a != b
    assert a.isalnum()


def test_candidates_carry_the_marker():
    m = confirm.new_marker()
    cands = confirm._finding_candidates(["html", "attribute"], m)
    assert cands and all(m in p for p in cands)
    assert any("onerror=alert('%s')" % m in p for p in cands)


def test_run_without_targets_is_safe():
    res = confirm.run([], [])
    assert res["confirmed"] == 0 and res["candidates"] == 0


def test_run_unsupported_reports_not_supported(monkeypatch):
    monkeypatch.setattr(confirm, "available", lambda: False)
    res = confirm.run([{"method": "GET", "url": "http://h/?q=1", "param": "q"}])
    assert res["supported"] is False and res["confirmed"] == 0


@NEEDS_PW
def test_confirm_get_reflected_html(server):
    f = {"method": "GET", "url": server + "/reflect?q=1", "param": "q",
         "context": "html", "contexts": ["html"], "verified": False}
    res = confirm.run([f])
    assert res["confirmed"] == 1
    assert f["verified"] is True
    assert f["severity"] == "critical"
    assert f["confirm_marker"] in f["verified_payload"]


@NEEDS_PW
def test_confirm_attribute_breakout(server):
    f = {"method": "GET", "url": server + "/attr?x=1", "param": "x",
         "context": "attribute", "contexts": ["attribute"], "verified": False}
    res = confirm.run([f])
    assert res["confirmed"] == 1 and f["verified"] is True


@NEEDS_PW
def test_confirm_post_reflected(server):
    f = {"method": "POST", "url": server + "/post-reflect", "param": "q",
         "context": "html", "contexts": ["html"], "verified": False}
    res = confirm.run([f])
    assert res["confirmed"] == 1 and f["verified"] is True


@NEEDS_PW
def test_escaped_output_not_confirmed(server):
    f = {"method": "GET", "url": server + "/safe?q=1", "param": "q",
         "context": "html", "contexts": ["html"], "verified": False}
    res = confirm.run([f])
    assert res["confirmed"] == 0 and f["verified"] is False


@NEEDS_PW
def test_escaped_attribute_not_confirmed(server):
    f = {"method": "GET", "url": server + "/escattr?q=1", "param": "q",
         "context": "attribute", "contexts": ["attribute"], "verified": False}
    res = confirm.run([f])
    assert f["verified"] is False


@NEEDS_PW
def test_site_own_alert_not_attributed(server):
    f = {"method": "GET", "url": server + "/selfalert?zzz=1", "param": "zzz",
         "context": "html", "contexts": ["html"], "verified": False}
    res = confirm.run([f])
    assert res["confirmed"] == 0 and f["verified"] is False


@NEEDS_PW
def test_confirm_dom_hash_decode(server):
    d = {"url": server + "/domdecode", "sources": ["location.hash"],
         "sinks": ["innerhtml"], "verified": False}
    res = confirm.run([], [d])
    assert res["dom_confirmed"] == 1
    assert d["verified"] is True and d["verified_via"] == "hash"
    assert d["poc"].startswith(server + "/domdecode#")


@NEEDS_PW
def test_confirm_dom_eval(server):
    d = {"url": server + "/domeval", "sources": ["location.hash"],
         "sinks": ["eval("], "verified": False}
    assert confirm.run([], [d])["dom_confirmed"] == 1


@NEEDS_PW
def test_confirm_dom_name(server):
    d = {"url": server + "/domname", "sources": ["window.name"],
         "sinks": ["innerhtml"], "verified": False}
    assert confirm.run([], [d])["dom_confirmed"] == 1


@NEEDS_PW
def test_confirm_dom_message(server):
    d = {"url": server + "/dommsg", "sources": ["postmessage"],
         "sinks": ["innerhtml"], "verified": False}
    assert confirm.run([], [d])["dom_confirmed"] == 1


@NEEDS_PW
def test_plain_hash_without_decode_not_confirmed(server):
    d = {"url": server + "/dom", "sources": ["location.hash"],
         "sinks": ["innerhtml"], "verified": False}
    confirm.run([], [d])
    assert d["verified"] is not True


def test_dom_pass_is_lead_only(server):
    result = scanner.scan(_client(), [server + "/dom"], threads=2)
    assert result["dom"], "expected a static DOM lead"
    for d in result["dom"]:
        assert d["verified"] is False
        assert d["severity"] == "info"
        assert "poc" not in d and "payload" not in d


@NEEDS_PW
def test_end_to_end_reflect_confirmed_and_reported(server):
    result = scanner.scan(_client(), [server + "/reflect?q=1"],
                          payloads_list=payloads.DEFAULT, threads=2)
    assert result["findings"], "static pass should produce a candidate"
    csum = confirm.run(result["findings"], result["dom"])
    result["confirm"] = csum
    assert csum["confirmed"] >= 1
    out = report.render(result)
    assert "DOGRULANDI" in out
    assert "FP'siz" in out


@NEEDS_PW
def test_end_to_end_safe_has_no_confirmed(server):
    result = scanner.scan(_client(), [server + "/safe?q=1"],
                          payloads_list=payloads.DEFAULT, threads=2)
    csum = confirm.run(result["findings"], result["dom"])
    assert csum["confirmed"] == 0
