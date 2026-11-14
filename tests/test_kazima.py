from xpars import detect, scanner


def test_char_survival_script_unicode_escape_not_survived():
    mk = "xqaa11bbqx"
    body = '<script>var u="https://x/?q=' + mk + '\\u003c\\u003e\\u0022";</script>'
    surv = detect.char_survival(body, mk)
    assert not any(surv[c] for c in "<>\"'")


def test_char_survival_app_markup_after_marker_not_survived():
    mk = "xqaa11bbqx"
    body = "<div>" + mk + "%3Csvg%3E ok</div><svg viewBox=\"0 0 1 1\"></svg>"
    surv = detect.char_survival(body, mk)
    assert surv["<"] is False
    assert surv['"'] is False


def test_breaks_survive_tag_needs_raw_lt():
    empty = {c: False for c in detect.PROBE_TAIL}
    assert detect.breaks_survive("<svg onload=alert(1)>", empty) is False
    assert detect.breaks_survive("<svg", empty) is False
    live = dict(empty); live["<"] = True
    assert detect.breaks_survive("<svg onload=alert(1)>", live) is True


def test_breaks_survive_quote_payload():
    empty = {c: False for c in detect.PROBE_TAIL}
    assert detect.breaks_survive("'-alert(1)-'", empty) is False
    q = dict(empty); q["'"] = True
    assert detect.breaks_survive("'-alert(1)-'", q) is True


def test_breaks_survive_scheme_payload_passes():
    empty = {c: False for c in detect.PROBE_TAIL}
    assert detect.breaks_survive("javascript:alert(1)", empty) is True


def test_cap_per_host_limits_and_prefers_params():
    urls = ["https://a.test/1", "https://a.test/2?x=1", "https://a.test/3",
            "https://a.test/4?y=1", "https://b.test/1?z=1"]
    out = scanner.cap_per_host(urls, 2)
    a = [u for u in out if "a.test" in u]
    assert len(a) == 2
    assert all("?" in u for u in a)
    assert "https://b.test/1?z=1" in out


def test_cap_per_host_zero_is_unlimited():
    urls = ["https://a.test/1", "https://a.test/2", "https://a.test/3"]
    assert scanner.cap_per_host(urls, 0) == urls


def test_spray_order_interleaves_hosts():
    urls = ["https://a/1", "https://a/2", "https://a/3", "https://b/1", "https://c/1"]
    out = scanner.spray_order(urls)
    assert out[:3] == ["https://a/1", "https://b/1", "https://c/1"]
    assert out[3] == "https://a/2"


def test_build_finding_drops_native_svg_fp():
    mk = "xqmk12"
    body = "<div>" + mk + "%3Csvg%3E ok</div><svg viewBox=\"0 0 1 1\"></svg>"

    def send(p):
        class R:
            status_code = 200
            headers = {"Content-Type": "text/html"}
            text = body
        return R()

    pr = scanner._probe_reflection(send, mk)
    f = scanner._build_finding(pr, "GET", "http://t/x?q=1", "q", mk,
                               ["<svg onload=alert(1)>", "<svg"], send, None, False)
    assert f is None
