import os
import sys

from . import cli

try:
    _code = cli.main()
except KeyboardInterrupt:
    _code = 130
    cli._INTERRUPTED = True

if getattr(cli, "_INTERRUPTED", False):
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(130)

sys.exit(_code)
