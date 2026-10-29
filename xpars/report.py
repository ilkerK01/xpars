from __future__ import annotations

import html as htmllib
import json
import shlex
import sys
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


def poc_url(f):
    method = f.get("method", "GET")
    payload = f.get("payload") or ""
    url = f.get("url", "")
    name = f.get("param", "")
    if method in ("GET", "CSTI-GET"):
        try:
            return params.set_param(url, name, payload)
        except Exception:
            return None
    if method == "PATH":
        idx = f.get("path_index")
        try:
            return params.set_path_segment(url, idx, quote(payload, safe=""))
        except Exception:
            return None
    return None


def _sorted_findings(result):
    return sorted(result.get("findings", []),
                  key=lambda f: SEV_RANK.get(f.get("severity", "high"), 1))


def _tty():
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _tick():
    return "\033[92m✓\033[0m" if _tty() else "✓"


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
        tag = (_tick() + " [XSS-DOGRULANDI]") if item.get("verified") else "[XSS]"
        lines.append("%s %s %s" % (tag, item.get("method", "GET"), item["url"]))
        lines.append("  severity: %s  (%s)" % (item.get("severity", "high"),
                                               item.get("how", "")))
        if item.get("waf"):
            lines.append("  waf     : %s" % item["waf"])
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
        pu = poc_url(item)
        if pu:
            lines.append("  ac      : %s" % pu)

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
            lines.append("%s [DOM-DOGRULANDI] %s" % (_tick(), d["url"]))
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
            if d.get("how"):
                lines.append("  tur     : %s" % d["how"])
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
    hv = result.get("harvest") or {}
    secrets = hv.get("secrets") or []
    cands = hv.get("candidates") or {}
    if secrets or any(cands.values()):
        lines.append("")
        lines.append("== HASAT: %d sir, aday uc LFI:%d RCE:%d SQLi:%d XSS:%d ==" % (
            len(secrets), len(cands.get("lfi", [])), len(cands.get("rce", [])),
            len(cands.get("sqli", [])), len(cands.get("xss", []))))
        for s in secrets[:30]:
            lines.append("  [SIR] %s: %s" % (s.get("type"), s.get("value")))
        for k in ("lfi", "rce", "sqli", "xss"):
            for u in (cands.get(k) or [])[:15]:
                lines.append("  [%s] %s" % (k.upper(), u))
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
.toolbar{display:flex;gap:10px;margin:0 0 16px}
.btn{background:var(--card);border:1px solid var(--line);color:var(--fg);
border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--low)}
.charts{display:flex;gap:16px;flex-wrap:wrap;margin:0 0 20px}
.chart-box{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px 16px;flex:1;min-width:260px;max-width:460px}
.chart-box h3{margin:0 0 8px;font-size:13px;color:var(--mut);font-weight:600}
.shot{display:block;max-width:100%;border:1px solid var(--line);border-radius:8px;margin:8px 0}
@media print{body{background:#fff;color:#000}.toolbar{display:none}
.card,.chart-box,table{break-inside:avoid}}
"""


_CHART_JS = """
(function(){
  var el=document.getElementById('xpars-data');
  if(!el||typeof Chart==='undefined')return;
  var d;try{d=JSON.parse(el.textContent||'{}');}catch(e){return;}
  var sev=document.getElementById('sevChart');
  var ctx=document.getElementById('ctxChart');
  try{ if(sev) new Chart(sev,{type:'doughnut',
    data:{labels:['kritik','yuksek','orta','dusuk'],
      datasets:[{data:d.sev||[],backgroundColor:['#ff4d6d','#ff9f43','#ffd166','#4dabf7']}]},
    options:{plugins:{legend:{labels:{color:'#9aa3b2'}}}}}); }catch(e){}
  try{ if(ctx) new Chart(ctx,{type:'bar',
    data:{labels:d.ctxLabels||[],
      datasets:[{data:d.ctxValues||[],backgroundColor:'#4dabf7'}]},
    options:{plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#9aa3b2'}},y:{beginAtZero:true,ticks:{color:'#9aa3b2'}}}}}); }catch(e){}
})();
"""


def _esc(x):
    return htmllib.escape(str(x if x is not None else ""))


def to_html(result, target="scan"):
    findings = _sorted_findings(result)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.get("severity", "high")] = counts.get(f.get("severity", "high"), 0) + 1
    ctx_counts = {}
    for f in findings:
        for c in (f.get("contexts") or [f.get("context")]):
            if c:
                ctx_counts[c] = ctx_counts.get(c, 0) + 1
    chart_data = {
        "sev": [counts.get("critical", 0), counts.get("high", 0),
                counts.get("medium", 0), counts.get("low", 0)],
        "ctxLabels": list(ctx_counts.keys()),
        "ctxValues": list(ctx_counts.values()),
    }
    rows = []
    for f in findings:
        sev = f.get("severity", "high")
        ver = ('<span class="ver">&#10003;</span>' if f.get("verified")
               else '<span class="muted">hayir</span>')
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
    parts.append("<div class='toolbar'>"
                 "<button class='btn' onclick='window.print()'>PDF olarak kaydet</button>"
                 "</div>")
    if findings:
        parts.append("<div class='charts'>"
                     "<div class='chart-box'><h3>Severite dagilimi</h3>"
                     "<canvas id='sevChart' height='220'></canvas></div>"
                     "<div class='chart-box'><h3>Baglam dagilimi</h3>"
                     "<canvas id='ctxChart' height='220'></canvas></div></div>")
    if findings:
        parts.append("<div class='sec'>Bulgular</div>")
        parts.append("<table><tr><th>severity</th><th>method</th><th>url</th>"
                     "<th>param</th><th>baglam</th><th>how</th><th>dogrulandi</th>"
                     "<th>payload</th><th>poc</th></tr>" + "".join(rows) + "</table>")
        shots = [f for f in findings if f.get("screenshot")]
        if shots:
            parts.append("<div class='sec'>Ekran goruntuleri (dogrulanan)</div>")
            for f in shots:
                parts.append("<div class='muted'>%s %s param=%s</div>" % (
                    _esc(f.get("method", "GET")), _esc(f.get("url")), _esc(f.get("param"))))
                parts.append("<img class='shot' src='%s' alt='screenshot'>"
                             % _esc(f.get("screenshot")))
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
    hv = result.get("harvest") or {}
    sec_rows = []
    for s in (hv.get("secrets") or [])[:100]:
        sec_rows.append("<tr><td>%s</td><td><code>%s</code></td></tr>"
                        % (_esc(s.get("type")), _esc(s.get("value"))))
    cand_rows = []
    for k in ("lfi", "rce", "sqli", "xss"):
        for u in ((hv.get("candidates") or {}).get(k) or [])[:50]:
            cand_rows.append("<tr><td>%s</td><td><code>%s</code></td></tr>"
                             % (k.upper(), _esc(u)))
    if sec_rows:
        parts.append("<div class='sec'>Sizan sirlar / anahtarlar</div>")
        parts.append("<table><tr><th>tur</th><th>deger</th></tr>"
                     + "".join(sec_rows) + "</table>")
    if cand_rows:
        parts.append("<div class='sec'>Aday uclar (LFI/RCE/SQLi/XSS)</div>")
        parts.append("<table><tr><th>sinif</th><th>url</th></tr>"
                     + "".join(cand_rows) + "</table>")
    parts.append("<script type='application/json' id='xpars-data'>%s</script>"
                 % json.dumps(chart_data))
    parts.append("<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/"
                 "dist/chart.umd.min.js'></script>")
    parts.append("<script>%s</script>" % _CHART_JS)
    parts.append("</body></html>")
    return "".join(parts)
