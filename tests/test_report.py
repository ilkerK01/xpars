from __future__ import annotations

from xpars import report


def _result():
    return {
        "findings": [{
            "url": "http://h/a?q=1", "param": "q", "method": "GET",
            "context": "html", "severity": "high", "how": "raw-injection",
            "verified": False, "payload": '"><svg onload=alert(1)>',
            "working_payloads": [], "evidence": "<div>x</div>",
        }],
        "dom": [], "blind_sent": [],
        "wafs": [{"host": "h", "detected": [{"waf": "Cloudflare", "signal": "header:cf-ray"}],
                  "blocked": False}],
    }


def test_html_has_findings_and_waf():
    h = report.to_html(_result(), "http://h")
    assert "<html" in h.lower()
    assert "http://h/a?q=1" in h
    assert "Cloudflare" in h


def test_html_no_forbidden_glyphs():
    h = report.to_html(_result(), "http://h")
    assert "—" not in h
    assert "·" not in h


def test_html_escapes_payload():
    h = report.to_html(_result(), "http://h")
    assert "&lt;svg" in h
    assert "<svg onload=alert(1)>" not in h


def test_render_sorts_by_severity():
    res = {"findings": [
        {"url": "u1", "param": "q", "method": "GET", "context": "html",
         "severity": "high", "payload": "p", "working_payloads": [], "evidence": ""},
        {"url": "u2", "param": "q", "method": "GET", "context": "html",
         "severity": "critical", "payload": "p", "working_payloads": [], "evidence": ""},
    ], "dom": [], "blind_sent": []}
    out = report.render(res)
    assert out.index("u2") < out.index("u1")
