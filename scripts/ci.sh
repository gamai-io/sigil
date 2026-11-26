#!/usr/bin/env bash
# CI-equivalent checks. The stack suite starts its own services on free local
# ports, generates keys/tokens/TSA cert in a temp dir, and needs no secrets.
set -euo pipefail
python3 -m pip install --upgrade pip >/dev/null
pip install -e . pytest
python3 -m compileall -q sigil
sigil-vectors
python3 -c "import pkgutil,importlib,sigil; [importlib.import_module('sigil.'+m.name) for m in pkgutil.iter_modules(sigil.__path__)]; print('imports ok')"
python3 -m pytest -q tests/ --ignore=tests/test_conformance_stack.py

# Full conformance stack (pass SIGIL_CI_PORT_BASE=<n> if 18100+ is busy).
if [ "${SIGIL_CONFORMANCE_STACK:-1}" = "1" ]; then
  python3 -m pytest -q tests/test_conformance_stack.py -s
fi
