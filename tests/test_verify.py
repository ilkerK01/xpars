from __future__ import annotations

from xpars import verify


def test_available_is_bool():
    assert isinstance(verify.available(), bool)


def test_verify_empty_is_safe():
    res = verify.verify_findings([])
    assert res["verified"] == 0
    assert res["candidates"] == 0


def test_verify_without_playwright_reports_unsupported():
    if verify.available():
        return
    findings = [{
        "method": "GET", "url": "http://h/a?q=1", "param": "q",
        "payload": '"><svg onload=alert(1)>',
        "working_payloads": ['"><svg onload=alert(1)>'],
    }]
    res = verify.verify_findings(findings)
    assert res["supported"] is False
    assert res["candidates"] == 1
