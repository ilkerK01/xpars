from __future__ import annotations

from xpars import cli, discover, http


def test_find_reflecting_param(server):
    client = http.Client(timeout=5)
    found = discover.discover(client, server + "/greet",
                              wordlist=["a", "b", "name", "c", "d", "debug"])
    assert "name" in found


def test_find_anomaly_param(server):
    client = http.Client(timeout=5)
    found = discover.discover(client, server + "/hidden",
                              wordlist=["x", "y", "debug", "z"])
    assert "debug" in found


def test_no_fp_on_echo(server):
    client = http.Client(timeout=5)
    found = discover.discover(client, server + "/echoall",
                              wordlist=["debug", "name", "redirect", "test"])
    assert found == []


def test_no_fp_on_random(server):
    client = http.Client(timeout=5)
    found = discover.discover(client, server + "/rnd",
                              wordlist=["debug", "name", "redirect", "test"])
    assert found == []


def test_no_fp_on_static(server):
    client = http.Client(timeout=5)
    found = discover.discover(client, server + "/about",
                              wordlist=["debug", "name", "redirect", "test"])
    assert found == []


def test_post_discover(server):
    client = http.Client(timeout=5)
    found = discover.discover(client, server + "/post-reflect", method="POST",
                              wordlist=["a", "q", "b", "c"])
    assert "q" in found


def test_bisection_isolates_single(server):
    client = http.Client(timeout=5)
    big = ["p%d" % i for i in range(300)]
    big[150] = "debug"
    found = discover.discover(client, server + "/hidden", wordlist=big)
    assert found == ["debug"]


def test_bundled_wordlist_loads():
    names = discover.bundled()
    assert len(names) > 200
    assert "redirect" in names
    assert "debug" in names


def test_cli_discover(server, capsys):
    rc = cli.main(["-u", server + "/greet", "--discover", "--no-waf"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "kesif-param" in out
    assert "name" in out


def test_cli_discover_reports_params(server, capsys):
    rc = cli.main(["-u", server + "/hidden", "--discover", "--no-waf"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "KESIF-PARAM" in out
    assert "debug" in out
