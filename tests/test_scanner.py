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
