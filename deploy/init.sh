#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="${SIGIL_RUNTIME:-$ROOT/runtime}"
if [ "${SIGIL_RESET:-0}" = "1" ]; then rm -rf "$RUNTIME/data" "$RUNTIME/effects" "$RUNTIME/keys" "$RUNTIME/tls"; fi
mkdir -p "$RUNTIME/keys/kms" "$RUNTIME/keys/pub" "$RUNTIME/data" "$RUNTIME/effects" "$RUNTIME/tls"
chmod 700 "$RUNTIME" "$RUNTIME/keys" "$RUNTIME/keys/kms" "$RUNTIME/data" "$RUNTIME/effects" "$RUNTIME/tls"
chmod 755 "$RUNTIME/keys/pub"

python3 - "$RUNTIME" <<'PY'
import os, pathlib, secrets, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

root = pathlib.Path(sys.argv[1])
for name in ("gate-ed25519-1", "anchor-ed25519-1"):
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    p = root / "keys" / "kms" / (name + ".pem")
    p.write_bytes(priv); os.chmod(p, 0o600)
    pubname = "gate_ed25519_public.pem" if name.startswith("gate") else "anchor_ed25519_public.pem"
    q = root / "keys" / "pub" / pubname
    q.write_bytes(pub); os.chmod(q, 0o644)

for name in ("control_token", "approver_token", "lease_token", "kms_token"):
    p = root / "keys" / name
    p.write_text(secrets.token_hex(32) + "\n"); os.chmod(p, 0o600)
(root / "keys" / "kms" / "token").write_text((root / "keys" / "kms_token").read_text())
os.chmod(root / "keys" / "kms" / "token", 0o600)
print(f"initialized {root}")
PY

chown -R 65534:65534 "$RUNTIME/keys" "$RUNTIME/data" "$RUNTIME/effects" "$RUNTIME/tls"

if [ -n "${SIGIL_TLS_CERT:-}" ] && [ -n "${SIGIL_TLS_KEY:-}" ]; then
  cp "$SIGIL_TLS_CERT" "$RUNTIME/tls/fullchain.pem"
  cp "$SIGIL_TLS_KEY" "$RUNTIME/tls/privkey.pem"
fi

if [ ! -f "$RUNTIME/tls/fullchain.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365     -keyout "$RUNTIME/tls/privkey.pem" -out "$RUNTIME/tls/fullchain.pem"     -subj "/CN=sigil.local" >/dev/null 2>&1
fi

chown 65534:65534 "$RUNTIME/tls/privkey.pem" "$RUNTIME/tls/fullchain.pem"
chmod 600 "$RUNTIME/tls/privkey.pem"
chmod 644 "$RUNTIME/tls/fullchain.pem"
