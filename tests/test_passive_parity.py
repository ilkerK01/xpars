from xpars import passive


def test_parse_certspotter():
    data = [{"dns_names": ["api.ex.com", "*.ex.com"]}, {"dns_names": ["mail.ex.com"]}]
    out = passive.parse_certspotter(data, "ex.com")
    assert "https://api.ex.com/" in out
    assert "https://mail.ex.com/" in out
    assert not any("*" in u for u in out)


def test_parse_certspotter_empty():
    assert passive.parse_certspotter(None, "ex.com") == []


def test_parse_threatminer():
    data = {"status_code": "200", "results": ["api.ex.com", "mail.ex.com"]}
    out = passive.parse_threatminer(data, "ex.com")
    assert "https://api.ex.com/" in out
    assert "https://mail.ex.com/" in out


def test_parse_threatminer_empty():
    assert passive.parse_threatminer({}, "ex.com") == []


def test_new_sources_keyless():
    assert "certspotter" in passive.KEYLESS
    assert "threatminer" in passive.KEYLESS
