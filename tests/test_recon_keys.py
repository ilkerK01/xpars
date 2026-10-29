import os

from xpars import passive


def test_parse_securitytrails():
    data = {"subdomains": ["api", "mail"]}
    out = passive.parse_securitytrails(data, "ex.com")
    assert "https://api.ex.com/" in out
    assert "https://mail.ex.com/" in out


def test_parse_virustotal():
    data = {"data": [{"id": "api.ex.com"}, {"id": "mail.ex.com"}, {"id": "evil.com"}]}
    out = passive.parse_virustotal(data, "ex.com")
    assert "https://api.ex.com/" in out
    assert "https://mail.ex.com/" in out
    assert not any("evil.com" in u for u in out)


def test_key_sources_noop_without_key():
    assert passive.securitytrails("ex.com", None) == []
    assert passive.virustotal("ex.com", "") == []


def test_load_keys(tmp_path):
    p = os.path.join(str(tmp_path), "keys.conf")
    with open(p, "w", encoding="utf-8") as f:
        f.write("# comment\nsecuritytrails = ABC123\nvirustotal=XYZ\nbad line\n")
    keys = passive.load_keys(p)
    assert keys["securitytrails"] == "ABC123"
    assert keys["virustotal"] == "XYZ"
    assert "bad line" not in keys


def test_load_keys_missing_file():
    assert passive.load_keys("C:/no/such/file.conf") == {}
