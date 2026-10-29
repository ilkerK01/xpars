from __future__ import annotations

from xpars import cli, http, scanner


def test_scan_clears_stop_flag(server):
    scanner._STOP.set()
    result = scanner.scan(http.Client(timeout=5), [server + "/reflect?q=1"],
                          threads=2)
    assert scanner._STOP.is_set() is False
    assert result["interrupted"] is False


def test_cli_marks_interrupted(server, monkeypatch):
    def fake_scan(*a, **kw):
        return {"findings": [], "dom": [], "blind_sent": [], "interrupted": True}

    monkeypatch.setattr(scanner, "scan", fake_scan)
    cli._INTERRUPTED = False
    rc = cli.main(["--get", "-u", server + "/reflect?q=1", "--no-confirm",
                   "--threads", "2"])
    assert cli._INTERRUPTED is True
    assert rc == 0


def test_cli_not_interrupted_on_normal_run(server):
    cli._INTERRUPTED = False
    rc = cli.main(["--get", "-u", server + "/reflect?q=1", "--no-confirm",
                   "--threads", "2"])
    assert cli._INTERRUPTED is False
    assert rc == 0
