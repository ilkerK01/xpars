from __future__ import annotations

from xpars import http, waf


class FakeResp:
    def __init__(self, headers, status=200, text="", cookies=None):
        self.headers = headers
        self.status_code = status
        self.text = text
        self.cookies = cookies or []


def test_cloudflare_header():
    r = FakeResp({"Server": "cloudflare", "CF-RAY": "abc-FRA"})
    names = [d["waf"] for d in waf.fingerprint(r)]
    assert "Cloudflare" in names


def test_akamai_cookie():
    r = FakeResp({"Set-Cookie": "bm_sz=xyz; path=/"})
    names = [d["waf"] for d in waf.fingerprint(r)]
    assert "Akamai" in names


def test_incapsula_header():
    r = FakeResp({"X-Iinfo": "1-2-3", "X-CDN": "Incapsula"})
    names = [d["waf"] for d in waf.fingerprint(r)]
    assert "Imperva Incapsula" in names


def test_clean_response_no_waf():
    r = FakeResp({"Server": "nginx", "Content-Type": "text/html"})
    assert waf.fingerprint(r) == []


def test_blocked_status():
    assert waf.blocked(FakeResp({}, status=403))
    assert waf.blocked(FakeResp({}, status=429))
    assert not waf.blocked(FakeResp({}, status=200))


def test_fingerprint_host_live(server):
    client = http.Client(timeout=5)
    fp = waf.fingerprint_host(client, server + "/waf")
    names = [d["waf"] for d in fp["wafs"]]
    assert "Cloudflare" in names
