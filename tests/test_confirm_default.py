from xpars import cli, confirm


class A:
    def __init__(self, confirm=False, verify=False, no_confirm=False):
        self.confirm = confirm
        self.verify = verify
        self.no_confirm = no_confirm


def test_no_confirm_forces_off():
    assert cli._confirm_decision(A(no_confirm=True), True, True) is False
    assert cli._confirm_decision(A(confirm=True, no_confirm=True), True, True) is False


def test_explicit_confirm_forces_on():
    assert cli._confirm_decision(A(confirm=True), False, False) is True
    assert cli._confirm_decision(A(verify=True), False, False) is True


def test_default_on_only_when_available_and_tty():
    assert cli._confirm_decision(A(), True, True) is True
    assert cli._confirm_decision(A(), True, False) is False
    assert cli._confirm_decision(A(), False, True) is False


def test_trigger_js_has_parity_hooks():
    js = confirm._TRIGGER_JS
    assert "shadowRoot" in js
    assert "beginElement" in js
    assert "formaction" in js
