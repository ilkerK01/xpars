from __future__ import annotations

import concurrent.futures as cf
import re
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from . import refine

JS_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\.open|\.ajax|navigate|assign|replace)\(\s*['"]([^'"\s]+)['"]""")
JS_ASSIGN_RE = re.compile(
    r"""\b(?:href|src|url|action|endpoint|api|path)\s*[:=]\s*['"]([^'"\s]+)['"]""", re.I)
JS_PATH_RE = re.compile(r"""['"](/[A-Za-z0-9_\-./]+(?:\?[^'"\s]*)?)['"]""")
ABS_URL_RE = re.compile(r"""https?://[^\s'"<>()\\]+""")
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

CRAWLABLE_EXT = {"", "html", "htm", "php", "asp", "aspx", "jsp", "do", "action", "cgi"}


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.forms = []
        self.inline = []
        self._form = None
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("a", "link") and d.get("href"):
            self.links.append(d["href"])
        if tag == "script":
            if d.get("src"):
                self.scripts.append(d["src"])
            else:
                self._in_script = True
        if tag == "form":
            self._form = {"action": d.get("action", ""),
                          "method": (d.get("method") or "get").lower(),
                          "fields": [], "values": {}}
        if tag in ("input", "textarea", "select") and self._form is not None and d.get("name"):
            self._form["fields"].append(d["name"])
            self._form["values"][d["name"]] = d.get("value", "")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline.append(data)


def _form_url(page_url, form):
    action = refine.safe_join(page_url, form["action"] or page_url)
    if not action:
        return None
    parts = refine.safe_split(action)
    query = urlencode([(f, "1") for f in form["fields"]])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _js_endpoints(base, text):
    out = set()
    for m in ABS_URL_RE.findall(text):
        out.add(m)
    for rx in (JS_CALL_RE, JS_ASSIGN_RE, JS_PATH_RE):
        for m in rx.findall(text):
            if m.startswith("http"):
                out.add(m)
            elif m.startswith("/"):
                j = refine.safe_join(base, m)
                if j:
                    out.add(j)
    return out


def _is_page(url):
    return refine._ext(refine.safe_split(url).path) in CRAWLABLE_EXT


def _in_scope(url, seed_hosts, seed_rdns, mode, scope):
    if not scope.permitted(url):
        return False
    h = refine.host(url)
    if not h:
        return False
    if mode == "subdomains":
        return any(h == r or h.endswith("." + r) for r in seed_rdns)
    return h in seed_hosts


def _safe_get(client, url):
    try:
        return client.get(url)
    except Exception:
        return None


def _fetch_many(client, urls, threads):
    results = []
    with cf.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(_safe_get, client, u): u for u in urls}
        for fut in cf.as_completed(futures):
            results.append((futures[fut], fut.result()))
    return results


def _robots_sitemap(client, seed, seed_hosts, seed_rdns, mode, scope):
    out = set()
    parts = refine.safe_split(seed)
    base = "%s://%s" % (parts.scheme, parts.netloc)
    robots = _safe_get(client, base + "/robots.txt")
    if robots is not None:
        for line in robots.text.splitlines():
            low = line.lower().strip()
            if low.startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path.startswith("/"):
                    cand = refine.safe_join(base, path)
                    if cand and _in_scope(cand, seed_hosts, seed_rdns, mode, scope):
                        out.add(cand)
            elif low.startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                out |= _read_sitemap(client, sm, seed_hosts, seed_rdns, mode, scope)
    out |= _read_sitemap(client, base + "/sitemap.xml", seed_hosts, seed_rdns, mode, scope)
    return out


def _read_sitemap(client, url, seed_hosts, seed_rdns, mode, scope):
    out = set()
    resp = _safe_get(client, url)
    if resp is None:
        return out
    for loc in LOC_RE.findall(resp.text):
        if _in_scope(loc, seed_hosts, seed_rdns, mode, scope):
            out.add(loc)
    return out


def _crawl_host(client, seeds, scope, seed_hosts, seed_rdns, depth, max_pages,
                threads, mode, include_js, robots, forms_out):
    visited = set()
    endpoints = set()
    frontier = set(seeds)
    if robots:
        for s in seeds:
            endpoints |= _robots_sitemap(client, s, seed_hosts, seed_rdns, mode, scope)
    level = 0
    while frontier and len(visited) < max_pages and level <= depth:
        batch = [u for u in frontier if u not in visited][:max_pages - len(visited)]
        frontier = set()
        for url, resp in _fetch_many(client, batch, threads):
            visited.add(url)
            if resp is None:
                continue
            endpoints.add(url)
            if "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            parser = _Parser()
            try:
                parser.feed(resp.text)
            except Exception:
                pass
            for form in parser.forms:
                if not form["fields"]:
                    continue
                if form["method"] == "get":
                    turl = _form_url(url, form)
                    if turl and _in_scope(turl, seed_hosts, seed_rdns, mode, scope):
                        endpoints.add(turl)
                elif form["method"] == "post" and forms_out is not None:
                    action = refine.safe_join(url, form["action"] or url)
                    action = action.split("#")[0] if action else None
                    if action and _in_scope(action, seed_hosts, seed_rdns, mode, scope):
                        forms_out.append({"action": action, "fields": form["fields"],
                                          "values": form.get("values", {})})
            for frag in parser.inline:
                for e in _js_endpoints(url, frag):
                    if _in_scope(e, seed_hosts, seed_rdns, mode, scope):
                        endpoints.add(e)
            for href in parser.links:
                absu = refine.safe_join(url, href)
                if not absu:
                    continue
                absu = absu.split("#")[0]
                if not absu.startswith(("http://", "https://")):
                    continue
                if not _in_scope(absu, seed_hosts, seed_rdns, mode, scope):
                    continue
                endpoints.add(absu)
                if _is_page(absu) and absu not in visited:
                    frontier.add(absu)
            if include_js:
                for src in parser.scripts:
                    jsu = refine.safe_join(url, src)
                    if not jsu:
                        continue
                    jsu = jsu.split("#")[0]
                    if not _in_scope(jsu, seed_hosts, seed_rdns, mode, scope) or jsu in visited:
                        continue
                    visited.add(jsu)
                    jr = _safe_get(client, jsu)
                    if jr is not None:
                        for e in _js_endpoints(jsu, jr.text):
                            if _in_scope(e, seed_hosts, seed_rdns, mode, scope):
                                endpoints.add(e)
        level += 1
    return endpoints


def discover(client, seeds, scope, depth=1, max_pages=60, threads=10,
             mode="strict", include_js=True, robots=True, forms_out=None,
             on_progress=None):
    seeds = [refine.normalize(s) for s in seeds]
    seeds = [s for s in seeds if scope.permitted(s)]
    if not seeds:
        return []
    seed_hosts = {refine.host(s) for s in seeds}
    seed_rdns = {refine.registered_domain(h) for h in seed_hosts}
    groups = {}
    for s in seeds:
        groups.setdefault(refine.host(s), []).append(s)
    ordered = sorted(groups)
    total = len(ordered)
    endpoints = set()
    for i, host in enumerate(ordered, 1):
        if on_progress is not None:
            try:
                on_progress(i, total, host)
            except Exception:
                pass
        try:
            endpoints |= _crawl_host(client, groups[host], scope, seed_hosts, seed_rdns,
                                     depth, max_pages, threads, mode, include_js,
                                     robots, forms_out)
        except Exception:
            continue
    return sorted(endpoints)
