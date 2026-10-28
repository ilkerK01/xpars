from __future__ import annotations

import json
import os

from xpars import cli


def test_full_scan(server, capsys):
    rc = cli.main(["--get", "-u", server + "/reflect?q=1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[XSS]" in out


def test_scope_block(capsys):
    rc = cli.main(["-u", "http://europa.eu/a?q=1"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "atlandi" in out


def test_json_output(server, tmp_path):
    outp = os.path.join(str(tmp_path), "r.json")
    rc = cli.main(["-u", server + "/reflect?q=1", "-o", outp])
    assert rc == 0
    with open(outp, encoding="utf-8") as f:
        data = json.load(f)
    assert data["findings"]


def test_detect_file_written(server, tmp_path):
    dp = os.path.join(str(tmp_path), "detect.txt")
    rc = cli.main(["-u", server + "/reflect?q=1", "--detect", dp])
    assert rc == 0
    assert os.path.exists(dp)
    with open(dp, encoding="utf-8") as f:
        body = f.read()
    assert "param=q" in body
    assert "payload=" in body


def test_detect_no_duplicate_lines(server, tmp_path):
    dp = os.path.join(str(tmp_path), "detect.txt")
    cli.main(["-u", server + "/reflect?q=1", "--detect", dp])
    with open(dp, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    keys = [ln.split("payload=")[0] for ln in lines]
    assert len(keys) == len(set(keys))


def test_crlf_cli(server, capsys):
    rc = cli.main(["-u", server + "/crlf-hdr?x=1", "--crlf"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CRLF" in out


def test_waf_in_output(server, capsys):
    rc = cli.main(["-u", server + "/waf?x=1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Cloudflare" in out


def test_no_waf_flag(server, capsys):
    rc = cli.main(["-u", server + "/waf?x=1", "--no-waf"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Cloudflare" not in out


def test_full_payloads_flag(server, capsys):
    rc = cli.main(["-u", server + "/app.js?x=1", "--full-payloads", "--no-waf"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "tam liste" in out
