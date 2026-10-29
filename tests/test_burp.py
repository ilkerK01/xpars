from xpars import burp


def test_parse_get_request():
    raw = "GET /search?q=1&p=2 HTTP/1.1\r\nHost: ex.com\r\nUser-Agent: x\r\n\r\n"
    req = burp.parse_request(raw)
    assert req["method"] == "GET"
    assert req["url"] == "https://ex.com/search?q=1&p=2"
    t = burp.to_target(req)
    assert t["kind"] == "get" and t["url"].endswith("q=1&p=2")


def test_parse_post_form():
    raw = ("POST /login HTTP/1.1\r\nHost: ex.com\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=b")
    t = burp.to_target(burp.parse_request(raw))
    assert t["kind"] == "post"
    assert "user" in t["fields"] and "pass" in t["fields"]
    assert t["values"]["user"] == "a"


def test_parse_post_json():
    raw = ('POST /api HTTP/1.1\r\nHost: ex.com\r\n'
           'Content-Type: application/json\r\n\r\n{"q": "x", "n": 1}')
    t = burp.to_target(burp.parse_request(raw))
    assert t["kind"] == "json"
    assert t["template"]["q"] == "x"


def test_parse_absolute_target():
    raw = "GET http://ex.com/a?b=1 HTTP/1.1\r\nHost: ex.com\r\n\r\n"
    assert burp.parse_request(raw)["url"] == "http://ex.com/a?b=1"


def test_parse_invalid():
    assert burp.parse_request("") is None
    assert burp.parse_request("garbage") is None
