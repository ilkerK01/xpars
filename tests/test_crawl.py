from __future__ import annotations

from xpars import crawl, http, scanner, scope


def _client():
    return http.Client(timeout=5)


def test_discover_finds_param_urls(server):
    urls = crawl.discover(_client(), [server + "/"], scope.Scope(), depth=1)
    assert any(u.endswith("/reflect?q=1") for u in urls)
    assert any("safe?q=2" in u for u in urls)


def test_discover_finds_form(server):
    urls = crawl.discover(_client(), [server + "/"], scope.Scope(), depth=1)
    assert any(u.endswith("/attr?x=1") for u in urls)


def test_discover_then_scan(server):
    urls = crawl.discover(_client(), [server + "/"], scope.Scope(), depth=1)
    result = scanner.scan(_client(), urls, threads=3)
    assert any(f["param"] == "q" and f["context"] == "html" for f in result["findings"])


def test_scope_blocks_crawl():
    urls = crawl.discover(_client(), ["http://europa.eu/"], scope.Scope(), depth=1)
    assert urls == []


def test_js_endpoint_discovery(server):
    urls = crawl.discover(_client(), [server + "/"], scope.Scope(), depth=1, include_js=True)
    assert any("/api/user?id=1" in u for u in urls)
    assert any("/search?q=2" in u for u in urls)


def test_cli_auto_pipeline(server, capsys):
    from xpars import cli
    host = server.replace("http://", "")
    rc = cli.main(["--get", "-u", host, "--auto", "--no-passive", "--izin", "--threads", "4"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[kesif]" in out
    assert "[XSS]" in out
