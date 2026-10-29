from __future__ import annotations

import os
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def parse_request(raw, default_scheme="https"):
    if not raw:
        return None
    text = raw.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    first = lines[0].split()
    if len(first) < 2:
        return None
    method = first[0].upper()
    target = first[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    host = headers.get("host", "")
    scheme = default_scheme
    if target.startswith("http://") or target.startswith("https://"):
        sp = urlsplit(target)
        scheme = sp.scheme
        host = sp.netloc or host
        path = urlunsplit(("", "", sp.path, sp.query, ""))
    else:
        path = target
    if not host:
        return None
    return {"method": method, "url": scheme + "://" + host + path,
            "headers": headers, "body": body,
            "content_type": headers.get("content-type", "").lower()}


def to_target(req):
    if req is None:
        return None
    method = req["method"]
    if method == "GET":
        return {"kind": "get", "url": req["url"]}
    ct = req.get("content_type", "")
    body = req.get("body", "")
    if "json" in ct:
        import json as _json
        try:
            tpl = _json.loads(body)
        except Exception:
            tpl = None
        if tpl is not None:
            return {"kind": "json", "action": req["url"], "template": tpl}
    pairs = parse_qsl(body, keep_blank_values=True)
    if pairs:
        return {"kind": "post", "action": req["url"],
                "fields": [k for k, _ in pairs], "values": dict(pairs)}
    return None


def load_folder(path, only_method=None):
    out = []
    try:
        names = sorted(os.listdir(path))
    except Exception:
        return out
    for nm in names:
        fp = os.path.join(path, nm)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except Exception:
            continue
        req = parse_request(raw)
        if req is None:
            continue
        if only_method and req["method"] != only_method:
            continue
        t = to_target(req)
        if t:
            out.append(t)
    return out
