from __future__ import annotations

from xpars import detect


def test_html_context():
    mk = "xqdeadbeefqx"
    body = "<div>" + mk + "'\"<></div>"
    assert detect.reflection(body, mk) == (True, "html", True)


def test_encoded_not_confirmed():
    mk = "xqdeadbeefqx"
    body = "<div>" + mk + "&#x27;&quot;&lt;&gt;</div>"
    reflected, context, confirmed = detect.reflection(body, mk)
    assert reflected is True
    assert confirmed is False
    assert context == "encoded"


def test_attribute_context():
    mk = "xqdeadbeefqx"
    body = '<input value="' + mk + "'\"&lt;&gt;" + '">'
    assert detect.reflection(body, mk) == (True, "attribute", True)


def test_not_reflected():
    assert detect.reflection("<html>nope</html>", "xqzzzzqx") == (False, "none", False)


def test_dom_sink_source():
    body = "<script>document.getElementById('o').innerHTML=location.hash;</script>"
    hits = detect.dom_findings(body)
    assert hits
    assert "location.hash" in hits[0]["sources"]
    assert "innerhtml" in hits[0]["sinks"]


def test_script_string_context():
    mk = "xqdeadbeefqx"
    body = '<html><script>track("' + mk + '\'"&lt;&gt;");</script></html>'
    assert detect.reflection(body, mk) == (True, "script", True)


def test_unquoted_attribute_context():
    mk = "xqdeadbeefqx"
    body = "<input value=" + mk + "'\"&lt;&gt;>"
    assert detect.reflection(body, mk) == (True, "attribute_unquoted", True)


def test_json_reflection_not_confirmed():
    mk = "xqdeadbeefqx"
    body = '{"q":"' + mk + "'\"<>" + '"}'
    reflected, context, confirmed = detect.reflection(body, mk, "application/json")
    assert reflected is True
    assert confirmed is False
    assert context == "json_reflection"


def test_html_confirmed_with_html_ct():
    mk = "xqdeadbeefqx"
    body = "<div>" + mk + "'\"<></div>"
    assert detect.reflection(body, mk, "text/html") == (True, "html", True)
