from __future__ import annotations

import html as htmllib
from urllib.parse import unquote

from xpars import crawl, http, params, payloads, scanner


def _client():
    return http.Client(timeout=5)


def test_crawl_unescapes_amp_entity():
    pages = {"http://w.test/": '<a href="/list?Country=All&amp;Health_topic=All">x</a>'}

    class _R:
        def __init__(self, t):
            self.text = t
            self.status_code = 200
            self.headers = {"Content-Type": "text/html"}

    class _C:
        def get(self, u, **kw):
            return _R(pages.get(u, "<html>ok</html>"))

    class _S:
        def permitted(self, u):
            return "w.test" in u

    urls = crawl.discover(_C(), ["http://w.test/"], _S(), depth=1, robots=False,
                          include_js=False)
    target = [u for u in urls if "list" in u]
    assert target
    keys = params.injectable(target[0])
    assert "Health_topic" in keys
    assert not any(k.startswith("amp;") for k in keys)


def _resp(body):
    class _R:
        text = body
    return _R()


def test_path_scan_futile_classifies():
    scanner._PATH_FUTILE.clear()

    class _Encoded:
        def get(self, u, **kw):
            return _resp("<div>" + htmllib.escape(unquote(u.rsplit("/", 1)[-1])) + "</div>")

    class _Raw:
        def get(self, u, **kw):
            return _resp("<div>" + unquote(u.rsplit("/", 1)[-1]) + "</div>")

    class _NoEcho:
        def get(self, u, **kw):
            return _resp("<div>not found</div>")

    assert scanner._path_scan_futile(_Encoded(), "http://enc.test/a") is True
    assert scanner._path_scan_futile(_Raw(), "http://raw.test/a") is False
    assert scanner._path_scan_futile(_NoEcho(), "http://none.test/a") is False


def test_path_scan_skipped_when_futile(server, monkeypatch):
    monkeypatch.setattr(scanner, "_path_scan_futile", lambda c, u: True)
    result = scanner.scan(_client(), [server + "/pathrefl/seed"], path_scan=True,
                          payloads_list=payloads.DEFAULT)
    assert not any(f["method"] == "PATH" for f in result["findings"])
