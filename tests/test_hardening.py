from __future__ import annotations

from xpars import http, scanner


def test_dedup_findings_merges_working():
    a = {"method": "GET", "url": "u", "param": "q", "context": "html",
         "working_payloads": ["x"]}
    b = {"method": "GET", "url": "u", "param": "q", "context": "html",
         "working_payloads": ["y"]}
    out = scanner.dedup_findings([a, b])
    assert len(out) == 1
    assert set(out[0]["working_payloads"]) == {"x", "y"}


def test_dedup_keeps_distinct_contexts():
    a = {"method": "GET", "url": "u", "param": "q", "context": "html",
         "working_payloads": []}
    b = {"method": "GET", "url": "u", "param": "q", "context": "attribute",
         "working_payloads": []}
    assert len(scanner.dedup_findings([a, b])) == 2


def test_findings_have_severity_and_how(server):
    result = scanner.scan(http.Client(timeout=5), [server + "/reflect?q=1"], threads=2)
    assert result["findings"]
    for f in result["findings"]:
        assert f["severity"] in ("critical", "high", "medium", "low")
        assert "how" in f
        assert f["verified"] is False
