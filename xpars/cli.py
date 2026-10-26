from __future__ import annotations

import argparse
import random
import sys
from urllib.parse import parse_qsl, urlsplit

from . import (blind, confirm, crawl, discover as discover_mod, http,
               params as paramlib, passive, payloads, refine, report, scanner,
               scope, stored, verify, waf)


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
    p.add_argument("--rps", type=float, default=0.0)
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
    p.add_argument("--no-passive", dest="passive", action="store_false")
    p.add_argument("--passive-sources", dest="passive_sources")
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
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--html", dest="html_output")
    p.add_argument("--izin", action="store_true")
    p.add_argument("-o", "--output", dest="output")
    p.add_argument("--version", action="version", version="xpars 0.1.0")
    p.set_defaults(passive=True, waf=True)
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


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.clear:
        print("\033[2J\033[H", end="")
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
    if not args.izin:
        print("xpars canli hedeflere payload GONDERIR.")
        print("yalnizca sahip oldugun ya da yetkili oldugun hedeflerde calistir.")
        print("onaylamak icin --izin ekle.")
        return 2
    if args.shuffle:
        random.shuffle(permitted)
    client = http.Client(timeout=args.timeout, delay=args.delay,
                         headers=args.headers, cookie=args.cookie,
                         user_agent=args.user_agent, proxy=args.proxy,
                         verify=not args.insecure, rps=args.rps)
    mode = "subdomains" if args.subdomains else "strict"
    post_forms = []
    if args.auto and not args.scope_allow:
        hosts = sorted({refine.host(u) for u in permitted})
        allow = (sorted({refine.registered_domain(h) for h in hosts})
                 if args.subdomains else hosts)
        sc = scope.Scope(allow=allow,
                         deny=(args.scope_deny.split(",") if args.scope_deny else None))
    all_endpoints = list(permitted)
    if args.auto or args.crawl is not None:
        collected = []
        if args.auto and args.passive:
            if args.passive_sources:
                psources = [s.strip() for s in args.passive_sources.split(",") if s.strip()]
            else:
                psources = ["wayback", "urlscan", "otx"]
                if args.subdomains:
                    psources += ["crtsh", "hackertarget"]
            for d in sorted({refine.host(u) for u in permitted}):
                found = passive.gather(d, subdomains=args.subdomains, sources=psources)
                collected += found
                print("[pasif] %s (%s) -> %d url" % (d, ",".join(psources), len(found)))
        depth = args.crawl if args.crawl is not None else (2 if args.auto else 1)
        collected += crawl.discover(client, permitted, sc, depth=depth,
                                    max_pages=args.max_pages, threads=args.threads,
                                    mode=mode, forms_out=post_forms)
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
            pkey = (refine.host(u), urlsplit(u).path)
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
    if not targets and not post_forms and not json_forms and not json_templates \
            and not graphql and not args.header_scan:
        print("test edilecek hedef yok (domain icin --auto, POST icin --data ekle)")
        return 1
    if args.full_payloads:
        payload_list = payloads.load_full()
        print("[payload] tam liste: %d payload" % len(payload_list))
    else:
        payload_list = payloads.load(args.payloads_file)
    if args.auto or args.crawl is not None:
        dom_list = list(all_endpoints)
        if args.header_scan or args.path_scan:
            get_scan_list = list(all_endpoints)
        else:
            get_scan_list = list(targets)
    else:
        dom_list = list(targets)
        get_scan_list = list(targets)
    result = scanner.scan(client, get_scan_list, threads=args.threads,
                          payloads_list=payload_list, blind=args.blind,
                          post_forms=post_forms, crlf=args.crlf,
                          stop_on_confirm=args.stop_on_confirm, evade=args.evade,
                          header_scan=args.header_scan, json_forms=json_forms,
                          path_scan=args.path_scan, multipart=args.multipart,
                          json_templates=json_templates, csti=args.csti,
                          graphql=graphql, dom_urls=dom_list)
    if args.header_scan and not targets:
        extra = []
        for u in permitted:
            extra += scanner.scan_headers(client, u, payload_list, args.evade)
        result["findings"] = scanner.dedup_findings(result["findings"] + extra)
    if args.stored:
        if args.auto or args.crawl is not None:
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
    if args.blind_url or args.blind_listen:
        header_urls = list(permitted) if args.header_scan else []
        bres = blind.run(client, callback=args.blind_url, get_targets=list(targets),
                         forms=post_forms, header_urls=header_urls,
                         listen=args.blind_listen, wait=args.blind_wait)
        result["blind"] = bres
        print("[blind] callback %s, %d enjeksiyon, %d geri-arama, %d dogrulanan"
              % (bres.get("callback"), len(bres.get("log", [])),
                 len(bres.get("hits", [])), len(bres.get("confirmed", []))))
    result["discovered"] = discovered
    result["wafs"] = []
    if args.waf:
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
    if args.confirm or args.verify:
        if not confirm.available():
            print("[dogrulama] Playwright kurulu degil - kesinlik (FP'siz) modu "
                  "atlandi. Kurulum: py -3.11 -m pip install playwright && "
                  "py -3.11 -m playwright install chromium")
        csum = confirm.run(result["findings"], result["dom"],
                           timeout=args.confirm_timeout)
        result["confirm"] = csum
        if csum.get("supported"):
            print("[dogrulama] %d/%d bulgu, %d/%d DOM adayi tarayicida "
                  "yurutulerek dogrulandi (FP'siz)"
                  % (csum["confirmed"], csum["candidates"],
                     csum["dom_confirmed"], csum["dom_candidates"]))
        if args.confirmed_only:
            result["findings"] = [f for f in result["findings"] if f.get("verified")]
            result["dom"] = [d for d in result["dom"] if d.get("verified")]
    print(report.render(result))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report.to_json(result))
        print("\n[json] %s" % args.output)
    if args.html_output:
        target = permitted[0] if permitted else "scan"
        with open(args.html_output, "w", encoding="utf-8") as f:
            f.write(report.to_html(result, target))
        print("[html] %s" % args.html_output)
    if args.fail_on_finding and result["findings"]:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
