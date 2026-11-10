from xpars import detect, scanner


def test_char_survival_double_encoded_is_empty():
    mk = "xqaa11bbqx"
    body = "<p>Not found: /en/" + mk + "%253C%253E%2527%2522%2560%2528</p>"
    surv = detect.char_survival(body, mk)
    assert not any(surv[c] for c in "<>\"'")


def test_char_survival_url_encoded_is_empty():
    mk = "xqaa11bbqx"
    body = "<p>Search results for " + mk + "%3C%3E%27%22 returned nothing</p>"
    surv = detect.char_survival(body, mk)
    assert not any(surv[c] for c in "<>\"'")


def test_char_survival_raw_reflection_survives():
    mk = "xqaa11bbqx"
    body = "<div>" + mk + "\"><svg onload=x></div>"
    surv = detect.char_survival(body, mk)
    assert surv['"'] is True
    assert surv["<"] is True
    assert surv[">"] is True


def test_char_survival_ignores_far_markup():
    mk = "xqaa11bbqx"
    body = "<title>" + mk + "</title><body><div onclick=\"x\"></div></body>"
    surv = detect.char_survival(body, mk)
    assert surv['"'] is False


def test_reflected_context_without_working_is_not_confirmed():
    refs = [{"context": "html", "confirmed": True, "index": 0, "score": 100}]
    char_map = {c: False for c in detect.PROBE_TAIL}
    f = scanner._finding("PATH", "http://t/x", "path[1]:x", refs, char_map,
                         [], 404, "body", "xqmk")
    assert f["confidence"] == "reflected"


def test_working_payload_is_confirmed():
    refs = [{"context": "html", "confirmed": True, "index": 0, "score": 100}]
    char_map = {c: True for c in "<>\"'"}
    f = scanner._finding("GET", "http://t/x?q=1", "q", refs, char_map,
                         ["<svg onload=alert(1)>"], 200, "body", "xqmk")
    assert f["confidence"] == "confirmed"
