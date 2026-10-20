from __future__ import annotations

from xpars import passive


def test_parse_cdx_keeps_urls():
    text = ("http://ex.com/a?x=1\n"
            "https://ex.com/b?y=2\n"
            "garbage line\n"
            "   \n"
            "http://ex.com/c\n")
    out = passive.parse_cdx(text)
    assert "http://ex.com/a?x=1" in out
    assert "https://ex.com/b?y=2" in out
    assert "http://ex.com/c" in out
    assert not any("garbage" in u for u in out)


def test_parse_cdx_empty():
    assert passive.parse_cdx("") == []


def test_belongs_filters_offdomain_and_garbage():
    assert passive.belongs("http://testasp.vulnweb.com/a?x=1", "testasp.vulnweb.com")
    assert not passive.belongs("http://http://testasp.vulnweb.com/t/fit.txt", "testasp.vulnweb.com")
    assert not passive.belongs("http://evil.com/x", "testasp.vulnweb.com")


def test_belongs_subdomains():
    d = "vulnweb.com"
    assert passive.belongs("http://testasp.vulnweb.com/a?x=1", d, subdomains=True)
    assert not passive.belongs("http://testasp.vulnweb.com/a?x=1", d, subdomains=False)


def test_parse_urlscan():
    data = {"results": [
        {"page": {"url": "https://ex.com/a?x=1"}},
        {"page": {"url": "https://ex.com/b"}},
        {"task": {}},
    ]}
    out = passive.parse_urlscan(data)
    assert "https://ex.com/a?x=1" in out
    assert "https://ex.com/b" in out
    assert len(out) == 2


def test_parse_otx():
    data = {"url_list": [{"url": "https://ex.com/p?q=1"}, {"nope": 1}]}
    assert passive.parse_otx(data) == ["https://ex.com/p?q=1"]


def test_parse_crtsh_subdomains():
    data = [{"name_value": "api.ex.com\n*.ex.com"}, {"name_value": "mail.ex.com"}]
    out = passive.parse_crtsh(data, "ex.com")
    assert "https://api.ex.com/" in out
    assert "https://mail.ex.com/" in out
    assert not any("*" in u for u in out)


def test_parse_hackertarget():
    text = "api.ex.com,1.2.3.4\nmail.ex.com,5.6.7.8"
    out = passive.parse_hackertarget(text, "ex.com")
    assert "https://api.ex.com/" in out
    assert "https://mail.ex.com/" in out


def test_parse_hackertarget_error():
    assert passive.parse_hackertarget("error check your api key", "ex.com") == []
