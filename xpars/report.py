from __future__ import annotations

import html as htmllib
import json
import shlex
from urllib.parse import quote

from . import params

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def to_json(result, indent=2):
    return json.dumps(result, indent=indent, ensure_ascii=False)


def _q(s):
    return shlex.quote(str(s))


def poc(f):
    method = f.get("method", "GET")
    payload = f.get("payload") or ""
    url = f.get("url", "")
    name = f.get("param", "")
    if method == "GET":
        try:
            target = params.set_param(url, name, payload)
        except Exception:
            target = url
        return "curl -gsk " + _q(target)
    if method == "PATH":
        idx = f.get("path_index")
        try:
            target = params.set_path_segment(url, idx, quote(payload, safe=""))
        except Exception:
            target = url
        return "curl -gsk " + _q(target)
    if method == "STORED":
        smethod = f.get("source_method", "GET")
        surl = f.get("source_url", url)
        if smethod == "POST":
            inj = "curl -sk -X POST " + _q(surl) + " --data-urlencode " + _q(name + "=" + payload)
        else:
            try:
                ex = params.set_param(surl, name, payload)
            except Exception:
                ex = surl
            inj = "curl -gsk " + _q(ex)
        return inj + "  ; sonra ac: " + url
    if method == "POST":
        return "curl -sk -X POST " + _q(url) + " --data-urlencode " + _q(name + "=" + payload)
    if method == "POST-JSON":
        body = json.dumps({name: payload}, ensure_ascii=False)
        return ("curl -sk -X POST " + _q(url) + " -H 'Content-Type: application/json' -d "
                + _q(body))
    if method == "GRAPHQL":
        tpl = f.get("json_template")
        jp = f.get("json_path")
        if tpl is not None and jp is not None:
            from . import jsontpl
            body = json.dumps(jsontpl.set_at(tpl, tuple(jp), payload), ensure_ascii=False)
        else:
            body = json.dumps({"query": "", "variables": {name: payload}}, ensure_ascii=False)
        return ("curl -sk -X POST " + _q(url) + " -H 'Content-Type: application/json' -d "
                + _q(body))
    if method == "CSTI-GET":
        try:
            target = params.set_param(url, name, payload)
        except Exception:
            target = url
        return "curl -gsk " + _q(target)
    if method == "HEADER":
        return "curl -sk " + _q(url) + " -H " + _q(name + ": " + payload)
    if method == "COOKIE":
        return "curl -sk " + _q(url) + " -H " + _q("Cookie: xpars=" + payload)
    if method == "CRLF":
        return "curl -gski " + _q(url) + "   (param " + name + ")"
    return "curl -gsk " + _q(url)


def _sorted_findings(result):
    return sorted(result.get("findings", []),
                  key=lambda f: SEV_RANK.get(f.get("severity", "high"), 1))


def render(result):
    lines = ["xpars sonuc", "=" * 48]
    wafs = result.get("wafs") or []
    for w in wafs:
        names = ", ".join("%s (%s)" % (x["waf"], x["signal"]) for x in w.get("detected", []))
        flag = " [BLOKLU]" if w.get("blocked") else ""
        lines.append("[waf] %s -> %s%s" % (w.get("host", ""), names or "yok", flag))
        csp = w.get("csp") or {}
        if csp.get("present"):
            note = "inline script engelli" if csp.get("blocks_inline") else "var (inline serbest)"
            lines.append("[csp] %s -> %s" % (w.get("host", ""), note))
    v = result.get("verify")
    if v is not None:
        if v.get("supported"):
            lines.append("[dogrulama] tarayici ile %d/%d bulgu calisirken dogrulandi"
                         % (v.get("verified", 0), v.get("candidates", 0)))
            if v.get("dom_candidates"):
                lines.append("[dogrulama-dom] %d/%d DOM adayi tarayicida tetiklendi"
                             % (v.get("dom_verified", 0), v.get("dom_candidates", 0)))
        else:
            lines.append("[dogrulama] Playwright kurulu degil (atlandi, %d aday)"
                         % v.get("candidates", 0))
    c = result.get("confirm")
    if c is not None:
        if c.get("supported"):
            lines.append("[kesinlik] tarayicida yurutulerek %d/%d bulgu + %d/%d DOM "
                         "adayi DOGRULANDI (FP'siz, marker-atfi)"
                         % (c.get("confirmed", 0), c.get("candidates", 0),
                            c.get("dom_confirmed", 0), c.get("dom_candidates", 0)))
        else:
            lines.append("[kesinlik] Playwright yok - dogrulama atlandi; asagidaki "
                         "bulgular DOGRULANMAMIS adaylardir")
    disc = result.get("discovered") or []
    disc_params = sum(len(d.get("params", [])) for d in disc)
    nconf = len([f for f in result.get("findings", []) if f.get("verified")])
    ndconf = len([d for d in result.get("dom", []) if d.get("verified")])
    summary = "bulgu: %d  dom: %d  blind: %d  kesif: %d" % (
        len(result["findings"]), len(result["dom"]),
        len(result["blind_sent"]), disc_params)
    if c is not None:
        summary += "  | DOGRULANDI -> bulgu: %d  dom: %d" % (nconf, ndconf)
    lines.append(summary)
    for d in disc:
        lines.append("")
        lines.append("[KESIF-PARAM] %s (%s)" % (d.get("url", ""), d.get("method", "GET")))
        lines.append("  parametre: %s" % ", ".join(d.get("params", [])))
    allf = _sorted_findings(result)
    confirmed = [f for f in allf if f.get("verified")]
    candidates = [f for f in allf if not f.get("verified")]
    ran_confirm = result.get("confirm") is not None

    def emit_finding(item):
        lines.append("")
        tag = "[XSS-DOGRULANDI]" if item.get("verified") else "[XSS]"
        lines.append("%s %s %s" % (tag, item.get("method", "GET"), item["url"]))
        lines.append("  severity: %s  (%s)" % (item.get("severity", "high"),
                                               item.get("how", "")))
        lines.append("  param   : %s" % item["param"])
        ctxs = item.get("contexts") or [item.get("context")]
        lines.append("  baglam  : %s" % ", ".join(c for c in ctxs if c))
        if item.get("char_map"):
            lines.append("  ham-kar : %s" % item["char_map"])
        if item.get("csp"):
            lines.append("  csp     : %s (execution icin --confirm ile teyit et)" % item["csp"])
        lines.append("  payload : %s" % (item.get("payload") or ""))
        working = item.get("working_payloads") or []
        if working:
            lines.append("  calisan : %d payload" % len(working))
            for p in working[:5]:
                lines.append("    %s" % p)
        lines.append("  kanit   : %s" % (item.get("evidence", "")[:120]))
        lines.append("  poc     : %s" % poc(item))

    if confirmed:
        lines.append("")
        lines.append("== DOGRULANDI: %d bulgu (tarayicida yurutuldu, FP'siz) =="
                     % len(confirmed))
        for item in confirmed:
            emit_finding(item)
    if candidates:
        if confirmed or ran_confirm:
            lines.append("")
            note = "dogrulanamadi" if ran_confirm else "DOGRULANMADI -> --confirm ile teyit et"
            lines.append("== ADAY: %d bulgu (%s) ==" % (len(candidates), note))
        for item in candidates:
            emit_finding(item)

    dom = result.get("dom", [])
    dom_conf = [d for d in dom if d.get("verified")]
    dom_lead = [d for d in dom if not d.get("verified")]
    if dom_conf:
        lines.append("")
        lines.append("== DOM DOGRULANDI: %d (tarayicida yurutuldu) ==" % len(dom_conf))
        for d in dom_conf:
            lines.append("")
            lines.append("[DOM-DOGRULANDI] %s" % d["url"])
            lines.append("  kaynak  : %s" % ", ".join(d.get("sources", [])))
            lines.append("  sink    : %s" % ", ".join(d.get("sinks", [])))
            if d.get("verified_via"):
                lines.append("  kanal   : %s" % d["verified_via"])
            if d.get("script"):
                lines.append("  script  : %s" % d["script"])
            if d.get("payload"):
                lines.append("  payload : %s" % d["payload"])
            if d.get("poc"):
                lines.append("  poc     : %s" % d["poc"])
    if dom_lead:
        lines.append("")
        lines.append("== DOM IPUCU: %d (kod ici kaynak->sink, DOGRULANMADI, FP "
                     "olabilir; --confirm ile teyit et) ==" % len(dom_lead))
        for d in dom_lead:
            lines.append("")
            lines.append("[DOM-IPUCU] %s" % d["url"])
            lines.append("  kaynak  : %s" % ", ".join(d.get("sources", [])))
            lines.append("  sink    : %s" % ", ".join(d.get("sinks", [])))
            if d.get("script"):
                lines.append("  script  : %s" % d["script"])
    for b in result["blind_sent"]:
        lines.append("")
        lines.append("[BLIND gonderildi] %s param=%s" % (b["url"], b["param"]))
    blind = result.get("blind")
    if blind:
        lines.append("")
        lines.append("[BLIND-OOB] callback: %s" % (blind.get("callback") or ""))
        lines.append("  enjeksiyon: %d nokta, geri-arama: %d, dogrulanan: %d"
                     % (len(blind.get("log", [])), len(blind.get("hits", [])),
                        len(blind.get("confirmed", []))))
        for c in blind.get("confirmed", []):
            lines.append("  [TETIKLENDI] %s %s param=%s (mk=%s)"
                         % (c.get("method", ""), c.get("url", ""),
                            c.get("param", ""), c.get("marker", "")))
    return "\n".join(lines)


_CSS = """
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e6e8ec;--mut:#9aa3b2;
--crit:#ff4d6d;--high:#ff9f43;--med:#ffd166;--low:#4dabf7;--ok:#2ecc71}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--mut);margin:0 0 20px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px 16px;min-width:110px}
.card b{display:block;font-size:22px}
.card span{color:var(--mut);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);
vertical-align:top;font-size:13px}
th{color:var(--mut);font-weight:600;background:#12151b}
tr:last-child td{border-bottom:none}
code{background:#0b0d11;border:1px solid var(--line);border-radius:6px;
padding:1px 6px;font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
font-weight:700;color:#0b0d11}
.b-critical{background:var(--crit)}.b-high{background:var(--high)}
.b-medium{background:var(--med)}.b-low{background:var(--low)}
.ver{color:var(--ok);font-weight:700}
.muted{color:var(--mut)}
.sec{margin:24px 0 8px;font-size:15px}
"""


def _esc(x):
    return htmllib.escape(str(x if x is not None else ""))


def to_html(result, target="scan"):
    findings = _sorted_findings(result)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.get("severity", "high")] = counts.get(f.get("severity", "high"), 0) + 1
    rows = []
    for f in findings:
        sev = f.get("severity", "high")
        ver = '<span class="ver">evet</span>' if f.get("verified") else '<span class="muted">hayir</span>'
        rows.append(
            "<tr><td><span class='badge b-%s'>%s</span></td><td>%s</td>"
            "<td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><code>%s</code></td><td><code>%s</code></td></tr>" % (
                sev, _esc(sev), _esc(f.get("method", "GET")), _esc(f.get("url")),
                _esc(f.get("param")), _esc(", ".join(f.get("contexts") or [f.get("context")])),
                _esc(f.get("how")), ver, _esc(f.get("payload")), _esc(poc(f))))
    waf_rows = []
    for w in result.get("wafs") or []:
        names = ", ".join("%s" % x["waf"] for x in w.get("detected", [])) or "yok"
        waf_rows.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
            _esc(w.get("host")), _esc(names), "bloklu" if w.get("blocked") else "hayir"))
    dom_rows = []
    for d in result.get("dom", []):
        dom_rows.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
            _esc(d.get("url")), _esc(", ".join(d.get("sources", []))),
            _esc(", ".join(d.get("sinks", []))), _esc(d.get("payload"))))
    disc_rows = []
    for d in result.get("discovered", []):
        disc_rows.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
            _esc(d.get("url")), _esc(d.get("method", "GET")),
            _esc(", ".join(d.get("params", [])))))

    parts = []
    parts.append("<!doctype html><html lang='tr'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>xpars raporu</title><style>%s</style></head><body>" % _CSS)
    parts.append("<h1>xpars XSS raporu</h1>")
    parts.append("<p class='sub'>hedef: <code>%s</code></p>" % _esc(target))
    parts.append("<div class='cards'>")
    for key, label in (("critical", "kritik"), ("high", "yuksek"),
                       ("medium", "orta"), ("low", "dusuk")):
        parts.append("<div class='card'><b>%d</b><span>%s</span></div>"
                     % (counts.get(key, 0), label))
    parts.append("<div class='card'><b>%d</b><span>toplam bulgu</span></div>"
                 % len(findings))
    parts.append("</div>")
    if findings:
        parts.append("<div class='sec'>Bulgular</div>")
        parts.append("<table><tr><th>severity</th><th>method</th><th>url</th>"
                     "<th>param</th><th>baglam</th><th>how</th><th>dogrulandi</th>"
                     "<th>payload</th><th>poc</th></tr>" + "".join(rows) + "</table>")
    if waf_rows:
        parts.append("<div class='sec'>WAF / CDN</div>")
        parts.append("<table><tr><th>host</th><th>tespit</th><th>bloklu</th></tr>"
                     + "".join(waf_rows) + "</table>")
    if dom_rows:
        parts.append("<div class='sec'>DOM kaynak / sink</div>")
        parts.append("<table><tr><th>url</th><th>kaynak</th><th>sink</th><th>payload</th></tr>"
                     + "".join(dom_rows) + "</table>")
    if disc_rows:
        parts.append("<div class='sec'>Kesfedilen gizli parametreler</div>")
        parts.append("<table><tr><th>url</th><th>method</th><th>parametre</th></tr>"
                     + "".join(disc_rows) + "</table>")
    parts.append("</body></html>")
    return "".join(parts)
