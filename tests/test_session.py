import json

from xpars import http, session as session_mod


def test_client_applies_cookies():
    c = http.Client(cookies=[{"name": "sid", "value": "abc",
                              "domain": "ex.com", "path": "/"}])
    jar = {ck.name: ck.value for ck in c.session.cookies}
    assert jar.get("sid") == "abc"


def test_session_load_roundtrip(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({
        "cookies": [{"name": "sid", "value": "x", "domain": "ex.com", "path": "/"}],
        "origins": [{"origin": "http://ex.com",
                     "localStorage": [{"name": "k", "value": "v"}]}],
        "xpars_headers": {"authorization": "Bearer t"}}), encoding="utf-8")
    cookies, headers, storage = session_mod.load(str(p))
    assert cookies[0]["name"] == "sid"
    assert headers["authorization"] == "Bearer t"
    assert storage["cookies"] and storage["origins"]
    assert "xpars_headers" not in storage


def test_capture_session_without_playwright(monkeypatch, capsys):
    from xpars import cli
    monkeypatch.setattr(session_mod, "available", lambda: False)
    rc = cli.main(["--capture-session", "http://ex.com/login"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "Playwright" in out


def test_session_pipeline_loads(server, tmp_path, capsys):
    from xpars import cli
    hostport = server.split("//")[1]
    p = tmp_path / "s.json"
    p.write_text(json.dumps({
        "cookies": [{"name": "xsess", "value": "zzz",
                     "domain": hostport.split(":")[0], "path": "/"}],
        "origins": [], "xpars_headers": {"x-api-key": "k123"}}), encoding="utf-8")
    rc = cli.main(["--get", "-u", server + "/reflect?q=1", "--no-confirm",
                   "--session", str(p), "--threads", "2"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[oturum]" in out
    assert "1 cookie" in out
