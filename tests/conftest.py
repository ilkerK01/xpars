from __future__ import annotations

import html as htmllib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import pytest


class VulnHandler(BaseHTTPRequestHandler):
    GUEST = []

    def _send(self, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True)
        path = parts.path
        if path == "/reflect":
            v = q.get("q", [""])[0]
            self._send("<html><body><div>" + v + "</div></body></html>")
        elif path == "/safe":
            v = q.get("q", [""])[0]
            self._send("<html><body><div>" + htmllib.escape(v, quote=True) + "</div></body></html>")
        elif path == "/csti":
            v = q.get("q", [""])[0]
            v = v.replace("{{1337*1337}}", "1787569").replace("${1331*1333}", "1774223")
            self._send("<html><body><div>" + v + "</div></body></html>")
        elif path == "/jsonget":
            v = q.get("q", [""])[0]
            self._send('{"q":"' + v + '","items":[]}', "application/json; charset=utf-8")
        elif path == "/attr":
            v = q.get("x", [""])[0].replace("<", "&lt;").replace(">", "&gt;")
            self._send('<html><body><input value="' + v + '"></body></html>')
        elif path == "/dom":
            self._send("<html><body><div id=o></div>"
                       "<script>document.getElementById('o').innerHTML=location.hash;</script>"
                       "</body></html>")
        elif path == "/domdecode":
            self._send("<html><body><div id=o></div><script>"
                       "document.getElementById('o').innerHTML="
                       "decodeURIComponent(location.hash.slice(1));</script></body></html>")
        elif path == "/domeval":
            self._send("<html><body><script>"
                       "try{eval(location.hash.slice(1))}catch(e){}</script></body></html>")
        elif path == "/domsearch":
            self._send("<html><body><script>"
                       "document.write(decodeURIComponent(location.search.slice(1)));"
                       "</script></body></html>")
        elif path == "/domname":
            self._send("<html><body><div id=o></div><script>"
                       "document.getElementById('o').innerHTML=window.name;</script></body></html>")
        elif path == "/dommsg":
            self._send("<html><body><div id=o></div><script>"
                       "window.onmessage=function(e){document.getElementById('o')"
                       ".innerHTML=e.data;};</script></body></html>")
        elif path == "/selfalert":
            v = q.get("q", [""])[0]
            self._send("<html><body><div>" + v + "</div>"
                       "<script>alert(1)</script></body></html>")
        elif path == "/":
            self._send('<html><body>'
                       '<a href="/reflect?q=1">r</a>'
                       '<a href="/safe?q=2">s</a>'
                       '<a href="/about">about</a>'
                       '<form action="/attr" method="get"><input name="x"></form>'
                       '<form action="/post-reflect" method="post"><input name="q"></form>'
                       '<script src="/app.js"></script>'
                       '</body></html>')
        elif path == "/app.js":
            self._send("fetch('/api/user?id=1'); var u = '/search?q=2';",
                       "application/javascript")
        elif path == "/crlf-body":
            v = q.get("x", [""])[0]
            self._send("<html><body>" + v + "</body></html>")
        elif path == "/big":
            self._send("<html><body>" + ("A" * 8000) + "</body></html>")
        elif path == "/crlf-hdr":
            v = q.get("x", [""])[0]
            data = b"<html>ok</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            for part in v.split("\r\n"):
                if ":" in part and not part.lower().startswith("content-type"):
                    k, _, val = part.partition(":")
                    k = k.strip()
                    if k and "\n" not in k and "\r" not in k:
                        try:
                            self.send_header(k, val.strip())
                        except Exception:
                            pass
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/comment":
            v = q.get("q", [""])[0]
            self._send("<html><!-- " + v + " --></html>")
        elif path == "/textarea":
            v = q.get("q", [""])[0]
            self._send("<html><textarea>" + v + "</textarea></html>")
        elif path == "/title":
            v = q.get("q", [""])[0]
            self._send("<html><head><title>" + v + "</title></head><body>x</body></html>")
        elif path == "/style":
            v = q.get("q", [""])[0]
            self._send("<html><style>a{color:" + v + "}</style>x</html>")
        elif path == "/sqattr":
            v = q.get("q", [""])[0].replace("<", "&lt;").replace(">", "&gt;")
            self._send("<html><input value='" + v + "'></html>")
        elif path == "/sqscript":
            v = q.get("q", [""])[0]
            self._send("<html><script>var a='" + v + "';</script></html>")
        elif path == "/escattr":
            v = q.get("q", [""])[0]
            self._send('<html><input value="' + htmllib.escape(v, quote=True) + '"></html>')
        elif path == "/hrefjs":
            v = q.get("q", [""])[0].replace("<", "&lt;").replace(">", "&gt;")
            self._send('<html><a href="' + v + '">x</a></html>')
        elif path == "/wafblock":
            v = q.get("q", [""])[0]
            data = ("<html>Request blocked by WAF: " + v + "</html>").encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/waf":
            data = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "cloudflare")
            self.send_header("CF-RAY", "7a1b2c3d4e5f6789-FRA")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/hidden":
            if "debug" in q:
                self._send("<html><body>home"
                           "<!-- diagnostic trace enabled extra line here -->"
                           "</body></html>")
            else:
                self._send("<html><body>home</body></html>")
        elif path == "/greet":
            v = q.get("name", [None])[0]
            if v is not None:
                self._send("<html><body>hello " + v + "</body></html>")
            else:
                self._send("<html><body>hello guest</body></html>")
        elif path == "/echoall":
            self._send("<html><body>" + parts.query + "</body></html>")
        elif path == "/hdr":
            ua = self.headers.get("User-Agent", "")
            self._send("<html><body>agent: " + ua + "</body></html>")
        elif path == "/refhdr":
            ref = self.headers.get("Referer", "")
            self._send("<html><body>from: " + ref + "</body></html>")
        elif path == "/xff":
            xff = self.headers.get("X-Forwarded-For", "")
            self._send("<html><body>ip: " + xff + "</body></html>")
        elif path == "/cookie":
            ck = self.headers.get("Cookie", "")
            self._send("<html><body>ck: " + ck + "</body></html>")
        elif path == "/multi":
            v = q.get("q", [""])[0]
            self._send("<html><head><title>" + htmllib.escape(v)
                       + "</title></head><body><div>" + v + "</div></body></html>")
        elif path == "/rnd":
            import os as _os
            import random as _r
            self._send("<html><body>"
                       + _os.urandom(_r.randint(10, 60)).hex()
                       + "</body></html>")
        elif path == "/guestbook":
            self._send("<html><body>" + "".join(self.GUEST) + "</body></html>")
        elif path.startswith("/pathrefl/"):
            seg = unquote(path.split("/pathrefl/", 1)[1])
            self._send("<html><body><div>" + seg + "</div></body></html>")
        else:
            self._send("<html><body>ok</body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        q = parse_qs(body, keep_blank_values=True)
        if self.path == "/post-reflect":
            v = q.get("q", [""])[0]
            self._send("<html><body><div>" + v + "</div></body></html>")
        elif self.path == "/json-reflect":
            import json as _j
            try:
                obj = _j.loads(body)
            except Exception:
                obj = {}
            v = obj.get("q", "")
            self._send("<html><body><div>" + str(v) + "</div></body></html>")
        elif self.path == "/json-nested":
            import json as _j
            try:
                obj = _j.loads(body)
            except Exception:
                obj = {}
            try:
                v = obj["a"]["b"]
            except Exception:
                v = ""
            self._send("<html><body><div>" + str(v) + "</div></body></html>")
        elif self.path == "/graphql":
            import json as _j
            try:
                obj = _j.loads(body)
            except Exception:
                obj = {}
            v = (obj.get("variables") or {}).get("q", "")
            self._send('{"data":{"search":"' + str(v) + '"}}',
                       "application/json")
        elif self.path == "/graphql-html":
            import json as _j
            try:
                obj = _j.loads(body)
            except Exception:
                obj = {}
            v = (obj.get("variables") or {}).get("q", "")
            query = obj.get("query", "")
            self._send("<html><body>error near " + str(query) + " "
                       + str(v) + "</body></html>")
        elif self.path == "/mp-reflect":
            import re as _re
            m = _re.search(r'name="q"\r?\n\r?\n(.*?)\r?\n--', body, _re.S)
            self._send("<html><body><div>" + (m.group(1) if m else "") + "</div></body></html>")
        elif self.path == "/guestbook":
            self.GUEST.append(q.get("msg", [""])[0])
            self._send("<html><body>ok</body></html>")
        else:
            self._send("<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def server():
    srv = HTTPServer(("127.0.0.1", 0), VulnHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
