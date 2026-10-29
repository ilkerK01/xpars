import json as _j

from xpars import report


def _result():
    return {
        "findings": [
            {"method": "GET", "url": "http://ex.com/?q=1", "param": "q",
             "context": "html", "contexts": ["html"], "severity": "critical",
             "how": "browser-execution", "payload": "<svg onload=alert(1)>",
             "verified": True, "screenshot": "data:image/png;base64,AAAA"},
            {"method": "GET", "url": "http://ex.com/?p=1", "param": "p",
             "context": "attribute", "contexts": ["attribute"], "severity": "high",
             "how": "raw-injection", "payload": "x", "verified": False},
        ],
        "dom": [], "blind_sent": [], "wafs": [], "discovered": [],
    }


def test_html_has_charts_and_print():
    h = report.to_html(_result(), "ex.com")
    assert "chart.js@4.4.1" in h
    assert "sevChart" in h and "ctxChart" in h
    assert "window.print()" in h
    assert "xpars-data" in h


def test_html_has_screenshot():
    h = report.to_html(_result(), "ex.com")
    assert "data:image/png;base64,AAAA" in h
    assert "class='shot'" in h


def test_html_chart_data_counts():
    h = report.to_html(_result(), "ex.com")
    frag = h.split("id='xpars-data'>")[1].split("</script>")[0]
    data = _j.loads(frag)
    assert data["sev"][0] == 1
    assert data["sev"][1] == 1
    assert "html" in data["ctxLabels"]


def test_html_no_findings_still_valid():
    h = report.to_html({"findings": [], "dom": [], "blind_sent": [],
                        "wafs": [], "discovered": []}, "ex.com")
    assert "<html" in h and "window.print()" in h


def test_html_tick_for_verified():
    h = report.to_html(_result(), "ex.com")
    assert "&#10003;" in h
    assert ">hayir<" in h


def test_poc_url_get_and_path():
    f = {"method": "GET", "url": "http://ex.com/?x=1", "param": "x",
         "payload": "<svg onload=alert(1)>"}
    u = report.poc_url(f)
    assert u and "x=" in u and "svg" in u
    assert report.poc_url({"method": "POST", "url": "http://ex.com/", "param": "x",
                           "payload": "y"}) is None


def test_render_tick_text_and_openurl():
    res = _result()
    res["confirm"] = {"supported": True, "confirmed": 1, "candidates": 2,
                      "dom_confirmed": 0, "dom_candidates": 0}
    for f in res["findings"]:
        f["evidence"] = "x"
    txt = report.render(res)
    assert "✓" in txt
    assert "DOGRULANDI" in txt
    assert "ac      :" in txt
