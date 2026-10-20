from __future__ import annotations

import os
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

CHUNK_GET = 128
CHUNK_POST = 255
MAX_REQUESTS = 600
MAX_QUERY_LEN = 2000

BUNDLED_PARAMS = os.path.join(os.path.dirname(__file__), "data", "params.txt")

DEFAULT_PARAMS = [
    "id", "page", "p", "q", "s", "search", "query", "keyword", "keywords", "term",
    "tag", "category", "cat", "type", "sort", "order", "orderby", "dir", "filter",
    "view", "mode", "format", "output", "lang", "language", "locale", "country",
    "region", "currency", "limit", "offset", "start", "count", "size", "per_page",
    "page_id", "pid", "uid", "user", "userid", "user_id", "username", "name",
    "fname", "lname", "email", "mail", "phone", "tel",
    "token", "csrf", "csrf_token", "auth", "apikey", "api_key", "key", "secret",
    "sig", "signature", "hash", "nonce", "state", "code", "access_token",
    "refresh_token", "session", "sessid", "sid",
    "debug", "test", "dev", "env", "verbose", "trace", "admin", "is_admin", "role",
    "redirect", "redirect_uri", "redirect_url", "redir", "return", "return_url",
    "returnurl", "returnto", "next", "url", "uri", "link", "href", "dest",
    "destination", "target", "goto", "continue", "callback", "jsonp", "cb",
    "file", "filename", "filepath", "path", "folder", "document", "doc",
    "template", "tpl", "include", "inc", "action", "act", "cmd", "command", "exec",
    "func", "function", "method", "op", "operation", "do", "step",
    "data", "payload", "content", "body", "text", "message", "msg", "comment",
    "title", "subject", "description", "desc", "value", "val", "input", "field",
    "item", "product", "product_id", "order_id", "invoice", "amount", "price",
    "qty", "quantity", "date", "from", "to", "start_date", "end_date", "year",
    "month", "day", "time", "timestamp", "status", "active", "enabled", "show",
    "hide", "display", "theme", "color", "style", "width", "height", "img",
    "image", "src", "source", "ref", "referer", "referrer", "origin", "host",
    "domain", "ip", "port", "proxy", "download", "upload", "preview", "embed",
]


def _rand_name(n=7):
    al = "abcdefghijklmnopqrstuvwxyz"
    return "".join(secrets.choice(al) for _ in range(n))


def _canary():
    return "zx" + secrets.token_hex(5) + "zx"


def _existing(url):
    return parse_qsl(urlsplit(url).query, keep_blank_values=True)


def _build_get(url, base_pairs, names, value):
    parts = urlsplit(url)
    pairs = list(base_pairs)
    for name in names:
        pairs.append((name, value))
    query = urlencode(pairs, safe="")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _measure(client, url, method, base_pairs, names, value):
    if method == "POST":
        data = {k: v for k, v in base_pairs}
        for name in names:
            data[name] = value
        try:
            resp = client.post(url, data)
        except Exception:
            return None
    else:
        try:
            resp = client.get(_build_get(url, base_pairs, names, value))
        except Exception:
            return None
    try:
        body = resp.text
    except Exception:
        body = ""
    ctype = (resp.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
    try:
        hdr = frozenset(k.lower() for k in resp.headers.keys())
    except Exception:
        hdr = frozenset()
    final = urlsplit(getattr(resp, "url", url) or url).path
    redir = (len(getattr(resp, "history", []) or []) > 0, final)
    return {
        "code": getattr(resp, "status_code", 0),
        "ctype": ctype,
        "headers": hdr,
        "length": len(body),
        "lines": body.count("\n"),
        "words": len(body.split()),
        "redirect": redir,
        "body": body,
    }


def _define(fp1, fp2):
    factors = {}
    for key in ("code", "ctype", "headers", "length", "lines", "words", "redirect"):
        if fp1[key] == fp2[key]:
            factors[key] = fp1[key]
    return factors


def _refine(factors, fp):
    for key in list(factors.keys()):
        if fp.get(key) != factors[key]:
            del factors[key]
    return factors


def baseline(client, url, method, base_pairs):
    fp1 = _measure(client, url, method, base_pairs, [_rand_name()], _canary())
    fp2 = _measure(client, url, method, base_pairs, [_rand_name()], _canary())
    if fp1 is None or fp2 is None:
        return None, False
    probe = _canary()
    fp3 = _measure(client, url, method, base_pairs, [_rand_name()], probe)
    reflect_reliable = True
    if fp3 is not None and probe in fp3["body"]:
        reflect_reliable = False
    factors = _define(fp1, fp2)
    if fp3 is not None:
        factors = _refine(factors, fp3)
    if not reflect_reliable:
        for key in ("length", "lines", "words"):
            factors.pop(key, None)
    return factors, reflect_reliable


def _changed(factors, fp, canary, reflect_reliable):
    if reflect_reliable and canary in fp["body"]:
        return True, "reflection"
    for key, reason in (("code", "code"), ("redirect", "redirect"),
                        ("ctype", "content-type"), ("headers", "headers"),
                        ("lines", "lines"), ("words", "words"), ("length", "length")):
        if key in factors and fp.get(key) != factors[key]:
            return True, reason
    return False, ""


def _test(client, url, method, base_pairs, names, factors, reflect_reliable):
    canary = _canary()
    fp = _measure(client, url, method, base_pairs, names, canary)
    if fp is None:
        return False, ""
    return _changed(factors, fp, canary, reflect_reliable)


def load_wordlist(path):
    names = []
    seen = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#") and w not in seen:
                seen.add(w)
                names.append(w)
    return names or list(DEFAULT_PARAMS)


def bundled():
    try:
        return load_wordlist(BUNDLED_PARAMS)
    except Exception:
        return list(DEFAULT_PARAMS)


def discover(client, url, method="GET", wordlist=None, chunk=None,
             max_requests=MAX_REQUESTS):
    method = (method or "GET").upper()
    names = list(wordlist or DEFAULT_PARAMS)
    base_pairs = _existing(url)
    known = {k for k, _ in base_pairs}
    names = [n for n in names if n not in known]
    if not names:
        return []
    factors, reflect_reliable = baseline(client, url, method, base_pairs)
    if factors is None:
        return []
    if not factors and not reflect_reliable:
        return []
    size = chunk or (CHUNK_GET if method == "GET" else CHUNK_POST)
    if method == "GET":
        avg = (sum(len(n) for n in names) / len(names)) + 16
        size = min(size, max(1, int(MAX_QUERY_LEN / avg)))
    size = max(1, min(size, len(names)))
    queue = [names[i:i + size] for i in range(0, len(names), size)]
    confirmed = []
    seen = set()
    budget = max_requests
    while queue and budget > 0:
        group = queue.pop()
        changed, _reason = _test(client, url, method, base_pairs, group,
                                 factors, reflect_reliable)
        budget -= 1
        if not changed:
            continue
        if len(group) == 1:
            name = group[0]
            if name in seen:
                continue
            ok, _ = _test(client, url, method, base_pairs, [name],
                          factors, reflect_reliable)
            budget -= 1
            if ok:
                seen.add(name)
                confirmed.append(name)
            continue
        half = len(group) // 2
        queue.append(group[:half])
        queue.append(group[half:])
    return sorted(confirmed)
