"""Generate a new SIGIL Ed25519 key version (private in KMS dir, public in /pub)."""
from __future__ import annotations
import argparse, os, re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def rotate(role: str, key_id: str, kms_dir: str, pub_dir: str, force: bool = False) -> dict:
    if role not in ("gate", "anchor"):
        raise ValueError("role must be gate or anchor")
    if not re.fullmatch(rf"{role}-ed25519-[0-9]+", key_id):
        raise ValueError(f"key_id must match {role}-ed25519-N")
    os.makedirs(kms_dir, exist_ok=True)
    os.makedirs(pub_dir, exist_ok=True)
    priv_path = os.path.join(kms_dir, key_id + ".pem")
    pub_name = key_id.replace("-", "_") + "_public.pem"
    pub_path = os.path.join(pub_dir, pub_name)
    if not force and (os.path.exists(priv_path) or os.path.exists(pub_path)):
        raise FileExistsError("key files already exist; use --force")
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(priv_path, "wb") as f:
        f.write(priv)
    os.chmod(priv_path, 0o600)
    with open(pub_path, "wb") as f:
        f.write(pub)
    os.chmod(pub_path, 0o644)
    return {"role": role, "key_id": key_id, "private": priv_path, "public": pub_path}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["gate", "anchor"])
    p.add_argument("key_id")
    p.add_argument("--kms-dir", default=os.environ.get("SIGIL_KMS_DIR", "/kms"))
    p.add_argument("--pub-dir", default=os.environ.get("SIGIL_PUB_DIR", "/pub"))
    p.add_argument("--force", action="store_true")
    a = p.parse_args()
    print(rotate(a.role, a.key_id, a.kms_dir, a.pub_dir, a.force))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
