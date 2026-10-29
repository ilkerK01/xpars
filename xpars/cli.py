from __future__ import annotations

import argparse
import os
import random
import sys
import time
from urllib.parse import parse_qsl, urlsplit

from . import (blind, burp, confirm, crawl, dirscan, discover as discover_mod,
               http, params as paramlib, passive, payloads, refine, report,
               scanner, scope, session as session_mod, stored, verify, waf)

_GREEN = "\033[92m"
_RED = "\033[91m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_BOX = "╗╔╝╚═║"
BANNER_ART = (
    "██╗  ██╗██████╗  █████╗ ██████╗ ███████╗",
    "╚██╗██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝",
    " ╚███╔╝ ██████╔╝███████║██████╔╝███████╗",
    " ██╔██╗ ██╔═══╝ ██╔══██║██╔══██╗╚════██║",
    "██╔╝ ██╗██║     ██║  ██║██║  ██║███████║",
    "╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝",
)


def _enable_vt():
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass


def _colorize(line):
    out = []
    for ch in line:
        if ch == "█":
            out.append(_GREEN + ch)
        elif ch in _BOX:
            out.append(_RED + ch)
        else:
            out.append(ch)
    out.append(_RESET)
    return "".join(out)


def banner():
    try:
        if not sys.stderr.isatty():
            return
    except Exception:
        return
    _enable_vt()
    lines = [""]
    for row in BANNER_ART:
        lines.append("   " + _colorize(row))
    lines.append("")
    lines.append("   " + _GREEN + "xpars" + _RESET + _DIM
                 + "  reflected / DOM XSS tarayici  v0.1.0" + _RESET)
    lines.append("   " + _RED + "yalnizca sahip oldugun ya da yetkili hedeflerde kullan"
                 + _RESET)
    lines.append("")
    try:
        sys.stderr.write("\n".join(lines) + "\n")
    except Exception:
        try:
            sys.stderr.write("\n   XPARS  reflected / DOM XSS tarayici  v0.1.0\n"
                             "   yalnizca yetkili hedeflerde kullan\n\n")
        except Exception:
            pass


def _crawl_progress(done, total, host):
    try:
        if not sys.stderr.isatty():
            if total <= 1 or done == total or done % 10 == 0:
                sys.stderr.write("[crawl] %d/%d %s\n" % (done, total, host))
                sys.stderr.flush()
            return
        sys.stderr.write("\r\033[2K[crawl] %d/%d %s" % (done, total, host))
        if done == total:
            sys.stderr.write("\n")
        sys.stderr.flush()
    except Exception:
        pass


def _scan_progress(done, total, found):
    try:
        if not sys.stderr.isatty():
            if total <= 1 or done == total or done % 25 == 0:
                sys.stderr.write("[tarama] %d/%d hedef, %d bulgu\n" % (done, total, found))
                sys.stderr.flush()
            return
        sys.stderr.write("\r\033[2K[tarama] %d/%d hedef, %d bulgu" % (done, total, found))
        if done == total:
            sys.stderr.write("\n")
        sys.stderr.flush()
    except Exception:
        pass


def _dedup_forms(forms):
    out = []
    seen = set()
    for f in forms:
        key = (f["action"], tuple(sorted(f["fields"])))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def build_parser():
    p = argparse.ArgumentParser(prog="xpars")
    p.add_argument("--get", action="store_true")
    p.add_argument("-u", "--url", dest="url")
    p.add_argument("--urls", dest="urls_file")
    p.add_argument("--payloads", dest="payloads_file")
    p.add_argument("--full-payloads", dest="full_payloads", action="store_true")
    p.add_argument("--shuffle", action="store_true")
    p.add_argument("--clear", action="store_true")
    p.add_argument("-t", "--threads", type=int, default=8)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--blind", dest="blind")
    p.add_argument("-H", "--header", action="append", dest="headers")
    p.add_argument("--cookie")
    p.add_argument("--user-agent", dest="user_agent")
    p.add_argument("--scope", dest="scope_allow")
    p.add_argument("--exclude", dest="scope_deny")
    p.add_argument("--proxy")
    p.add_argument("--data", dest="data")
    p.add_argument("--crlf", action="store_true")
    p.add_argument("--json", dest="json_body", action="store_true")
    p.add_argument("--evade", action="store_true")
    p.add_argument("--header-scan", dest="header_scan", action="store_true")
    p.add_argument("--fail-on-finding", dest="fail_on_finding", action="store_true")
    p.add_argument("--stored", action="store_true")
    p.add_argument("--path-scan", dest="path_scan", action="store_true")
    p.add_argument("--harvest", action="store_true")
    p.add_argument("--rps", type=float, default=0.0)
    p.add_argument("--stealth", choices=["low", "medium", "high"], default=None)
    p.add_argument("--spray", action="store_true")
    p.add_argument("--multipart", action="store_true")
    p.add_argument("--json-data", dest="json_data", action="append")
    p.add_argument("--blind-url", dest="blind_url")
    p.add_argument("--blind-listen", dest="blind_listen")
    p.add_argument("--blind-wait", dest="blind_wait", type=float, default=0.0)
    p.add_argument("--graphql-url", dest="graphql_url")
    p.add_argument("--graphql-query", dest="graphql_query")
    p.add_argument("--graphql-vars", dest="graphql_vars")
    p.add_argument("--csti", action="store_true")
    p.add_argument("--brute-params", dest="brute_params", action="store_true")
    p.add_argument("--discover", action="store_true")
    p.add_argument("--discover-full", dest="discover_full", action="store_true")
    p.add_argument("--param-wordlist", dest="param_wordlist")
    p.add_argument("--discover-chunk", dest="discover_chunk", type=int, default=None)
    p.add_argument("--discover-method", dest="discover_method", default="GET")
    p.add_argument("--discover-endpoints", dest="discover_endpoints", type=int, default=25)
    p.add_argument("--stop-on-confirm", dest="stop_on_confirm", action="store_true")
    p.add_argument("--crawl", nargs="?", const=1, type=int, default=None)
    p.add_argument("--auto", action="store_true")
    p.add_argument("--passive", action="store_true")
    p.add_argument("--passive-sources", dest="passive_sources")
    p.add_argument("--passive-keys", dest="passive_keys")
    p.add_argument("--dirscan", action="store_true")
    p.add_argument("--no-waf", dest="waf", action="store_false")
    p.add_argument("--subdomains", action="store_true")
    p.add_argument("--max-pages", dest="max_pages", type=int, default=60)
    p.add_argument("--endpoints", dest="endpoints")
    p.add_argument("--aggressive-dedup", dest="aggressive_dedup", action="store_true")
    p.add_argument("--no-dedup", dest="no_dedup", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--confirm", action="store_true",
                   help="tarayicida yurutup FP'siz dogrula (marker-atfi)")
    p.add_argument("--confirmed-only", dest="confirmed_only", action="store_true",
                   help="sadece tarayicida dogrulanan bulgulari raporla")
    p.add_argument("--confirm-timeout", dest="confirm_timeout", type=float, default=8.0)
    p.add_argument("--no-confirm", dest="no_confirm", action="store_true")
    p.add_argument("--get-burp", dest="get_burp")
    p.add_argument("--post-burp", dest="post_burp")
    p.add_argument("--capture-session", dest="capture_session")
    p.add_argument("--session", dest="session")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="gonderilen her istegi ekrana yaz (stderr)")
    p.add_argument("--html", dest="html_output")
    p.add_argument("-o", "--output", dest="output")
    p.add_argument("--log", dest="logpath")
    p.add_argument("--detect", dest="detectpath", nargs="?", const="detect.txt",
                   default=None,
                   help="bulgu cikinca aninda detect dosyasina ekle (vars. detect.txt)")
    p.add_argument("--no-prefilter", dest="no_prefilter", action="store_true")
    p.add_argument("--version", action="version", version="xpars 0.1.0")
    p.set_defaults(waf=True)
    return p


def _normalize(url):
    if not url.lower().startswith(("http://", "https://")):
        return "http://" + url
    return url


def _load_urls(args):
    out = []
    if args.url:
        out.append(args.url)
    if args.urls_file:
        if args.urls_file == "-":
            out += [line.strip() for line in sys.stdin if line.strip()]
        else:
            with open(args.urls_file, encoding="utf-8", errors="replace") as f:
                out += [line.strip() for line in f if line.strip()]
    return [_normalize(u) for u in out]


def _isatty():
    try:
        return bool(sys.stderr.isatty())
    except Exception:
        return False


def _confirm_decision(args, available, is_tty):
    if getattr(args, "no_confirm", False):
        return False
    if args.confirm or args.verify:
        return True
    return bool(available and is_tty)


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.clear:
        print("\033[2J\033[H", end="")
    banner()
    if args.capture_session:
        out = args.session or "xpars-session.json"
        if not session_mod.available():
            print("[oturum] Playwright kurulu degil. Kurulum: py -3.11 -m pip "
                  "install playwright && py -3.11 -m playwright install chromium")
            return 2
        res = session_mod.capture(args.capture_session, out)
        if res.get("ok"):
            print("[oturum] kaydedildi -> %s (%d cookie, %d origin, header: %s)" % (
                out, res["cookies"], res["origins"],
                ", ".join(res["headers"]) or "yok"))
            return 0
        print("[oturum] yakalanamadi: %s" % res.get("reason"))
        return 1
    urls = _load_urls(args)
    if not urls:
        print("hedef yok: -u <url> ya da --urls <dosya> ver")
        return 2
    sc = scope.Scope(
        allow=(args.scope_allow.split(",") if args.scope_allow else None),
        deny=(args.scope_deny.split(",") if args.scope_deny else None))
    permitted = [u for u in urls if sc.permitted(u)]
    for u in urls:
        if u not in permitted:
            print("[atlandi] %s -> %s" % (u, sc.reason(u)))
    if not permitted:
        print("izinli hedef yok (kapsam disi)")
        return 2
    if args.shuffle:
        random.shuffle(permitted)
    session_state = None
    s_cookies = []
    if args.session:
        try:
            s_cookies, s_headers, session_state = session_mod.load(args.session)
        except Exception as exc:
            print("[oturum] yuklenemedi: %s" % type(exc).__name__)
            s_cookies, s_headers, session_state = [], {}, None
        if s_headers:
            args.headers = (args.headers or []) + ["%s: %s" % (k, v)
                                                   for k, v in s_headers.items()]
        print("[oturum] %s -> %d cookie, %d header" % (
            args.session, len(s_cookies), len(s_headers)))
    stealth = http.stealth_profile(args.stealth)
    client = http.Client(timeout=args.timeout,
                         delay=args.delay or stealth["delay"],
                         headers=args.headers, cookie=args.cookie,
                         user_agent=args.user_agent, proxy=args.proxy,
                         verify=not args.insecure,
                         rps=args.rps or stealth["rps"],
                         jitter=stealth["jitter"],
                         verbose=args.verbose, logpath=args.logpath,
                         cookies=s_cookies)
    mode = "subdomains" if args.subdomains else "strict"
    post_forms = []
    if (args.auto or args.passive) and not args.scope_allow:
        hosts = sorted({refine.host(u) for u in permitted})
        allow = (sorted({refine.registered_domain(h) for h in hosts})
                 if args.subdomains else hosts)
        sc = scope.Scope(allow=allow,
                         deny=(args.scope_deny.split(",") if args.scope_deny else None))
    all_endpoints = list(permitted)
    if args.auto or args.crawl is not None or args.passive:
        collected = []
        if args.passive:
            if args.passive_sources:
                psources = [s.strip() for s in args.passive_sources.split(",") if s.strip()]
            else:
                psources = ["wayback", "urlscan", "otx"]
                if args.subdomains:
                    psources += ["crtsh", "hackertarget", "certspotter", "threatminer"]
            pkeys = passive.load_keys(args.passive_keys) if args.passive_keys else {}
            if pkeys and args.subdomains:
                for ks in passive.KEY_SOURCES:
                    if ks in pkeys and ks not in psources:
                        psources.append(ks)
            for d in sorted({refine.host(u) for u in permitted}):
                found = passive.gather(d, subdomains=args.subdomains, sources=psources,
                                       keys=pkeys)
                collected += found
                print("[pasif] %s (%s) -> %d url" % (d, ",".join(psources), len(found)))
        if args.auto or args.crawl is not None:
            depth = args.crawl if args.crawl is not None else (2 if args.auto else 1)
            try:
                collected += crawl.discover(client, permitted, sc, depth=depth,
                                            max_pages=args.max_pages, threads=args.threads,
                                            mode=mode, forms_out=post_forms,
                                            on_progress=(None if args.verbose
                                                         else _crawl_progress))
            except Exception as exc:
                sys.stderr.write("[uyari] crawl hatasi, tohumlarla devam: %s\n"
                                 % type(exc).__name__)
                collected += list(permitted)
        collected = [u for u in collected if sc.permitted(u)]
        full = refine.refine(collected, params_only=False,
                             dedup=not args.no_dedup, collapse_numbers=args.aggressive_dedup)
        targets = refine.refine(collected, params_only=True,
                               dedup=not args.no_dedup, collapse_numbers=args.aggressive_dedup)
        all_endpoints = full
        post_forms = _dedup_forms(post_forms)
        print("[kesif] %d ham uc -> %d temiz -> %d parametreli hedef, %d POST form"
              % (len(collected), len(full), len(targets), len(post_forms)))
        if args.endpoints:
            with open(args.endpoints, "w", encoding="utf-8") as f:
                f.write("\n".join(full))
            print("[endpoints] %s" % args.endpoints)
    else:
        targets = permitted
    if args.dirscan:
        hits = []
        seen_d = set()
        for u in permitted:
            r = dirscan.root(u)
            if not r or not sc.permitted(r):
                continue
            for h in dirscan.scan(client, r):
                if h["url"] not in seen_d and sc.permitted(h["url"]):
                    seen_d.add(h["url"])
                    hits.append(h["url"])
        if hits:
            targets = list(targets) + hits
            all_endpoints = list(all_endpoints) + hits
            print("[dirscan] %d yol bulundu" % len(hits))
    json_forms = []
    if args.data:
        fields = [k for k, _ in parse_qsl(args.data, keep_blank_values=True)]
        if fields:
            for u in permitted:
                if args.json_body:
                    json_forms.append({"action": u, "fields": fields})
                else:
                    post_forms.append({"action": u, "fields": fields})
            targets = []
    json_templates = []
    if args.json_data:
        import json as _json
        for raw in args.json_data:
            try:
                tpl = _json.loads(raw)
            except Exception:
                print("[json-data] gecersiz JSON atlandi")
                continue
            for u in permitted:
                json_templates.append({"action": u, "template": tpl})
    graphql = None
    if args.graphql_query:
        gurl = args.graphql_url or (permitted[0] if permitted else None)
        gvars = {}
        if args.graphql_vars:
            import json as _jsonql
            try:
                gvars = _jsonql.loads(args.graphql_vars)
            except Exception:
                print("[graphql] gecersiz --graphql-vars JSON, bos kullanildi")
                gvars = {}
        if gurl:
            graphql = {"url": gurl, "query": args.graphql_query, "variables": gvars}
    if args.brute_params:
        bruted = []
        for u in all_endpoints:
            if "?" not in u and sc.permitted(u):
                bruted += paramlib.brute_candidates(u)
        if bruted:
            targets = list(targets) + bruted
            print("[brute] %d param-adayi uc eklendi" % len(bruted))
    discovered = []
    if args.discover:
        if args.param_wordlist:
            wl = discover_mod.load_wordlist(args.param_wordlist)
        elif args.discover_full:
            wl = discover_mod.bundled()
        else:
            wl = discover_mod.DEFAULT_PARAMS
        dmethod = "POST" if (args.discover_method or "").upper() == "POST" else "GET"
        print("[kesif-param] %d parametre adi, yontem %s" % (len(wl), dmethod))
        sample = []
        seen_paths = set()
        for u in list(targets) + list(permitted):
            if not sc.permitted(u):
                continue
            pkey = (refine.host(u), refine.safe_split(u).path)
            if pkey in seen_paths:
                continue
            seen_paths.add(pkey)
            sample.append(u)
            if len(sample) >= args.discover_endpoints:
                break
        for u in sample:
            try:
                found = discover_mod.discover(client, u, method=dmethod,
                                              wordlist=wl, chunk=args.discover_chunk)
            except Exception:
                found = []
            if found:
                discovered.append({"url": u, "method": dmethod, "params": found})
                print("[kesif-param] %s -> %d gizli parametre: %s"
                      % (u, len(found), ", ".join(found)))
                if dmethod == "POST":
                    post_forms.append({"action": u, "fields": found})
                else:
                    newu = u
                    for name in found:
                        newu = paramlib.add_param(newu, name, "1")
                    targets = list(targets) + [newu]
        if not discovered:
            print("[kesif-param] gizli parametre bulunamadi")
        post_forms = _dedup_forms(post_forms)
    if args.get_burp:
        bg = burp.load_folder(args.get_burp, only_method="GET")
        added = [t["url"] for t in bg if t["kind"] == "get" and sc.permitted(t["url"])]
        if added:
            targets = list(targets) + added
            print("[get-burp] %d GET istegi yuklendi" % len(added))
    if args.post_burp:
        bp = burp.load_folder(args.post_burp, only_method="POST")
        n = 0
        for t in bp:
            if not sc.permitted(t["action"]):
                continue
            if t["kind"] == "json":
                json_templates.append({"action": t["action"], "template": t["template"]})
                n += 1
            elif t["kind"] == "post":
                post_forms.append({"action": t["action"], "fields": t["fields"],
                                   "values": t.get("values")})
                n += 1
        post_forms = _dedup_forms(post_forms)
        if n:
            print("[post-burp] %d POST istegi yuklendi" % n)
    harvest_result = None
    if args.harvest:
        hsrc = (list(all_endpoints)
                if (args.auto or args.crawl is not None or args.passive)
                else list(permitted))
        try:
            harvest_result, hinject = scanner.harvest_collect(client, hsrc, sc.permitted)
        except Exception:
            harvest_result, hinject = None, []
        tset = set(targets)
        newh = [u for u in hinject if u not in tset]
        if newh:
            targets = list(targets) + newh
        print("[hasat] %d parametreli uc toplandi, %d yeni hedef taramaya eklendi"
              % (len(hinject), len(newh)))
    if not targets and not post_forms and not json_forms and not json_templates \
            and not graphql and not args.header_scan:
        print("test edilecek hedef yok (domain icin --auto, POST icin --data ekle)")
        return 1
    if args.full_payloads:
        payload_list = payloads.load_full()
        print("[payload] tam liste: %d payload" % len(payload_list))
    else:
        payload_list = payloads.load(args.payloads_file)
    if args.auto or args.crawl is not None or args.passive:
        dom_list = list(all_endpoints)
        if args.header_scan or args.path_scan:
            get_scan_list = list(all_endpoints)
        else:
            get_scan_list = list(targets)
    else:
        dom_list = list(targets)
        get_scan_list = list(targets)
    detect_seen = set()

    def _flush_detect(findings):
        if not args.detectpath:
            return
        new_lines = []
        for f in findings:
            key = (f.get("method"), f.get("url"), f.get("param"), f.get("context"))
            if key in detect_seen:
                continue
            detect_seen.add(key)
            ts = time.strftime("%H:%M:%S")
            sev = str(f.get("severity", "")).upper()
            vrf = "verified" if f.get("verified") else "reflected"
            pay = (f.get("payload") or "").replace("\n", " ").replace("\r", " ")
            new_lines.append(
                "[%s] %s %s %s %s param=%s ctx=%s payload=%s" % (
                    ts, sev, vrf, f.get("method", ""), f.get("url", ""),
                    f.get("param", ""), f.get("context", ""), pay))
        if not new_lines:
            return
        try:
            with open(args.detectpath, "a", encoding="utf-8") as f:
                f.write("\n".join(new_lines) + "\n")
                f.flush()
        except Exception:
            pass

    def _detect_line(f, mark):
        ts = time.strftime("%H:%M:%S")
        sev = str(f.get("severity", "")).upper()
        pay = (f.get("payload") or "").replace("\n", " ").replace("\r", " ")
        return "[%s] %s%s %s %s param=%s ctx=%s payload=%s" % (
            ts, mark, sev, f.get("method", ""), f.get("url", ""),
            f.get("param", ""), f.get("context", ""), pay)

    def _detect_split(findings):
        if not args.detectpath:
            return None
        root, ext = os.path.splitext(args.detectpath)
        conf_path = root + "-confirmed" + (ext or ".txt")
        unv = [f for f in findings if not f.get("verified")]
        ver = [f for f in findings if f.get("verified")]
        try:
            with open(args.detectpath, "w", encoding="utf-8") as fh:
                if unv:
                    fh.write("\n".join(_detect_line(f, "") for f in unv) + "\n")
        except Exception:
            pass
        if ver:
            try:
                with open(conf_path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(_detect_line(f, "✓ ") for f in ver) + "\n")
            except Exception:
                pass
        return conf_path, len(unv), len(ver)

    def _flush_report(res):
        findings = scanner.dedup_findings(res.get("findings", []))
        _flush_detect(findings)
        if not args.output and not args.html_output:
            return
        snap = dict(res)
        snap["findings"] = findings
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(report.to_json(snap))
            except Exception:
                pass
        if args.html_output:
            try:
                tgt = permitted[0] if permitted else "scan"
                with open(args.html_output, "w", encoding="utf-8") as f:
                    f.write(report.to_html(snap, tgt))
            except Exception:
                pass

    if args.spray:
        get_scan_list = scanner.spray_order(get_scan_list)
    result = scanner.scan(client, get_scan_list, threads=args.threads,
                          payloads_list=payload_list, blind=args.blind,
                          post_forms=post_forms, crlf=args.crlf,
                          stop_on_confirm=args.stop_on_confirm, evade=args.evade,
                          header_scan=args.header_scan, json_forms=json_forms,
                          path_scan=args.path_scan, multipart=args.multipart,
                          json_templates=json_templates, csti=args.csti,
                          graphql=graphql, dom_urls=dom_list,
                          prefilter=not args.no_prefilter, on_update=_flush_report,
                          on_progress=(None if args.verbose else _scan_progress),
                          do_harvest=False)
    interrupted = result.get("interrupted")
    if args.header_scan and not targets and not interrupted:
        extra = []
        for u in permitted:
            extra += scanner.scan_headers(client, u, payload_list, args.evade)
        result["findings"] = scanner.dedup_findings(result["findings"] + extra)
    if args.stored and not interrupted:
        if args.auto or args.crawl is not None or args.passive:
            pages = list(all_endpoints)
        else:
            pages = list(permitted)
        pages = [p for p in pages if sc.permitted(p)]
        get_targets = [t for t in targets if sc.permitted(t)]
        sfinds, ssent = stored.run(client, get_targets, post_forms, pages)
        if sfinds:
            result["findings"] = scanner.dedup_findings(result["findings"] + sfinds)
            print("[stored] %d kalici bulgu, %d enjeksiyon, %d sayfa"
                  % (len(sfinds), len(ssent), len(pages)))
        else:
            print("[stored] kalici yansima yok (%d enjeksiyon, %d sayfa)"
                  % (len(ssent), len(pages)))
    if (args.blind_url or args.blind_listen) and not interrupted:
        header_urls = list(permitted) if args.header_scan else []
        bres = blind.run(client, callback=args.blind_url, get_targets=list(targets),
                         forms=post_forms, header_urls=header_urls,
                         listen=args.blind_listen, wait=args.blind_wait)
        result["blind"] = bres
        print("[blind] callback %s, %d enjeksiyon, %d geri-arama, %d dogrulanan"
              % (bres.get("callback"), len(bres.get("log", [])),
                 len(bres.get("hits", [])), len(bres.get("confirmed", []))))
    result["discovered"] = discovered
    if args.harvest and harvest_result is not None:
        result["harvest"] = harvest_result
    if args.harvest:
        hv = result.get("harvest") or {}
        cnd = hv.get("candidates", {})
        print("[hasat] %d sir, aday uc LFI:%d RCE:%d SQLi:%d XSS:%d, %d endpoint"
              % (len(hv.get("secrets", [])), len(cnd.get("lfi", [])),
                 len(cnd.get("rce", [])), len(cnd.get("sqli", [])),
                 len(cnd.get("xss", [])), len(hv.get("endpoints", []))))
    result["wafs"] = []
    if args.waf and not interrupted:
        seen_hosts = set()
        for u in permitted:
            h = refine.host(u)
            if h and h not in seen_hosts:
                seen_hosts.add(h)
                fp = waf.fingerprint_host(client, u)
                result["wafs"].append({"host": h, "detected": fp["wafs"],
                                       "blocked": fp["blocked"],
                                       "csp": fp.get("csp", {})})
    csp_hosts = {}
    for w in result["wafs"]:
        csp = w.get("csp") or {}
        if csp.get("blocks_inline"):
            csp_hosts[w["host"]] = True
    if csp_hosts:
        for f in result["findings"]:
            if refine.host(f.get("url", "")) in csp_hosts:
                f["csp"] = "blocks-inline"
    do_confirm = _confirm_decision(args, confirm.available(), _isatty())
    if do_confirm and not interrupted:
        if not confirm.available():
            print("[dogrulama] Playwright kurulu degil - kesinlik (FP'siz) modu "
                  "atlandi. Kurulum: py -3.11 -m pip install playwright && "
                  "py -3.11 -m playwright install chromium")
        try:
            csum = confirm.run(result["findings"], result["dom"],
                               timeout=args.confirm_timeout, capture=True,
                               storage_state=session_state)
        except Exception as exc:
            sys.stderr.write("[uyari] dogrulama hatasi, dogrulanmamis raporlaniyor: %s\n"
                             % type(exc).__name__)
            csum = {"supported": False, "confirmed": 0,
                    "candidates": len(result["findings"]),
                    "dom_confirmed": 0, "dom_candidates": len(result["dom"])}
        result["confirm"] = csum
        if csum.get("supported"):
            print("[dogrulama] %d/%d bulgu, %d/%d DOM adayi tarayicida "
                  "yurutulerek dogrulandi (FP'siz)"
                  % (csum["confirmed"], csum["candidates"],
                     csum["dom_confirmed"], csum["dom_candidates"]))
        if args.confirmed_only:
            result["findings"] = [f for f in result["findings"] if f.get("verified")]
            result["dom"] = [d for d in result["dom"] if d.get("verified")]
    split = _detect_split(scanner.dedup_findings(result.get("findings", [])))
    if split:
        conf_path, nunv, nver = split
        print("[detect] %d dogrulanmamis -> %s" % (nunv, args.detectpath))
        if nver:
            print("[confirmed] %d dogrulanmis (tik) -> %s" % (nver, conf_path))
    try:
        print(report.render(result))
    except Exception:
        pass
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report.to_json(result))
            print("\n[json] %s" % args.output)
        except Exception as exc:
            sys.stderr.write("[uyari] json yazilamadi: %s\n" % type(exc).__name__)
    if args.html_output:
        try:
            target = permitted[0] if permitted else "scan"
            with open(args.html_output, "w", encoding="utf-8") as f:
                f.write(report.to_html(result, target))
            print("[html] %s" % args.html_output)
        except Exception as exc:
            sys.stderr.write("[uyari] html yazilamadi: %s\n" % type(exc).__name__)
    if args.fail_on_finding and result["findings"]:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
