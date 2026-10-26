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


def test_discover_per_host_budget(monkeypatch):
    calls = []

    def fake_host(client, seeds, sc, seed_hosts, seed_rdns, depth, max_pages,
                  threads, mode, include_js, robots, forms_out):
        calls.append((sorted(seeds), max_pages))
        return {sorted(seeds)[0]}

    monkeypatch.setattr(crawl, "_crawl_host", fake_host)

    class AllowAll:
        def permitted(self, u):
            return True

    prog = []
    out = crawl.discover(None,
                         ["http://a.test/", "http://b.test/", "http://a.test/x"],
                         AllowAll(), max_pages=7,
                         on_progress=lambda d, t, h: prog.append((d, t, h)))
    assert len(calls) == 2
    assert all(mp == 7 for _, mp in calls)
    assert [p[0] for p in prog] == [1, 2]
    assert prog[-1][1] == 2
    assert len(out) == 2


def test_safe_url_helpers_never_raise():
    from xpars import refine
    bad = "http://[notipv6]/x"
    assert refine.safe_split(bad).hostname in (None, "")
    assert refine.host(bad) == ""
    refine.normalize(bad)
    refine.normalize("http://h:notaport/")
    assert isinstance(refine.safe_join("http://a.test/", "/ok"), str)
    refine.safe_join("http://a.test/", bad)


def test_scope_handles_bad_url():
    bad = "http://[notipv6]/x"
    assert scope.host_of(bad) == ""
    assert scope.Scope().permitted(bad) is False
    assert crawl._in_scope(bad, set(), set(), "strict", scope.Scope()) is False


def test_dom_pass_handles_bad_url():
    class _R:
        text = "<html><a href=\"http://[notipv6]/y\">x</a></html>"

    class _Stub:
        def get(self, u):
            return _R()

    out = scanner._dom_pass(_Stub(), ["http://[notipv6]/x", "http://ok.test/"])
    assert isinstance(out, list)


def test_client_verbose_logs_requests(server, capsys):
    c = http.Client(timeout=5, verbose=True)
    c.get(server + "/reflect?q=1")
    err = capsys.readouterr().err
    assert "[req]" in err
    assert "GET" in err


def test_cli_auto_pipeline(server, capsys):
    from xpars import cli
    host = server.replace("http://", "")
    rc = cli.main(["--get", "-u", host, "--auto", "--threads", "4"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[kesif]" in out
    assert "[XSS]" in out
