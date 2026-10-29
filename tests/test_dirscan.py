from xpars import dirscan


def test_root():
    assert dirscan.root("https://ex.com/a/b?x=1") == "https://ex.com/"
    assert dirscan.root("notaurl") is None


def test_candidates():
    cs = dirscan.candidates("https://ex.com/")
    assert "https://ex.com/admin" in cs
    assert "https://ex.com/.git/config" in cs
    assert all(c.startswith("https://ex.com/") for c in cs)


def test_classify():
    assert dirscan.classify(200) is True
    assert dirscan.classify(301) is True
    assert dirscan.classify(403) is True
    assert dirscan.classify(404) is False
    assert dirscan.classify(500) is False


def test_scan_catch_all(server):
    from xpars import http
    client = http.Client(timeout=5)
    out = dirscan.scan(client, server + "/")
    assert out == []
