from xpars import harvest


def test_secrets_aws_jwt():
    t = ("key AKIAABCDEFGHIJKLMNOP and "
         "tok eyJ0123456789abc.eyJ0123456789def.0123456789sigx")
    r = harvest.scan(t)
    types = {s["type"] for s in r["secrets"]}
    assert "AWS Access Key ID" in types
    assert "JWT" in types


def test_endpoint_candidates():
    t = ("var a='/download?file=x'; fetch('/run?cmd=ls'); "
         "u='/p?q=1'; x='/item?id=5';")
    r = harvest.scan(t)
    assert any("file=" in u for u in r["candidates"]["lfi"])
    assert any("cmd=" in u for u in r["candidates"]["rce"])
    assert any("q=1" in u for u in r["candidates"]["xss"])
    assert any("id=5" in u for u in r["candidates"]["sqli"])


def test_private_key():
    t = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    r = harvest.scan(t)
    assert any(s["type"] == "Private Key Block" for s in r["secrets"])


def test_merge_dedup():
    a = harvest.scan("AKIAABCDEFGHIJKLMNOP")
    b = harvest.scan("AKIAABCDEFGHIJKLMNOP")
    harvest.merge(a, b)
    aws = [s for s in a["secrets"] if s["type"] == "AWS Access Key ID"]
    assert len(aws) == 1


def test_empty():
    r = harvest.scan("")
    assert r["secrets"] == [] and r["endpoints"] == []


def test_harvest_collect_feeds_targets():
    from xpars import scanner

    pages = {
        "http://a.test/": ('<a href="/search?q=1">x</a>'
                           '<script src="/app.js"></script>'
                           '<a href="http://evil.test/p?x=1">y</a>'),
        "http://a.test/app.js": 'fetch("/api/item?id=5"); var u="/noparam";',
    }

    class _R:
        def __init__(self, t):
            self.text = t

    class _C:
        def get(self, u, **kw):
            return _R(pages.get(u, ""))

    def permitted(u):
        return "a.test" in u

    agg, inject = scanner.harvest_collect(_C(), ["http://a.test/"], permitted)
    assert any("search?q=1" in u for u in inject)
    assert any("item?id=5" in u for u in inject)
    assert all("evil.test" not in u for u in inject)
    assert all("?" in u for u in inject)
