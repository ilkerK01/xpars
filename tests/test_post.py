from __future__ import annotations

from xpars import cli, crawl, http, scanner, scope


def _client():
    return http.Client(timeout=5)


def test_post_form_reflection(server):
    result = scanner.scan(_client(), [], threads=2,
                          post_forms=[{"action": server + "/post-reflect", "fields": ["q"]}])
    finding = [f for f in result["findings"] if f["method"] == "POST"]
    assert finding
    assert finding[0]["context"] == "html"
    assert finding[0]["param"] == "q"


def test_crawl_collects_post_form(server):
    forms = []
    crawl.discover(_client(), [server + "/"], scope.Scope(), depth=1, forms_out=forms)
    assert any(f["action"].endswith("/post-reflect") and "q" in f["fields"] for f in forms)


def test_cli_data_post(server, capsys):
    rc = cli.main(["-u", server + "/post-reflect", "--data", "q=1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "POST" in out
    assert "[XSS]" in out


def test_proxy_configured():
    client = http.Client(proxy="http://127.0.0.1:8080")
    assert client.session.proxies.get("http") == "http://127.0.0.1:8080"
    assert client.session.proxies.get("https") == "http://127.0.0.1:8080"
