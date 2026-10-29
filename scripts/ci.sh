#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install --upgrade pip >/dev/null
pip install -e .
python3 -m compileall -q sigil
sigil-vectors
python3 -c "import pkgutil,importlib,sigil; [importlib.import_module('sigil.'+m.name) for m in pkgutil.iter_modules(sigil.__path__)]; print('imports ok')"
