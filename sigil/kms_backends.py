"""KMS/HSM signature backends. Cloud backends are adapters; credentials are external."""
from __future__ import annotations
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

ALG = "ecdsa-p256-sha256"

class P256FileKMS:
    """Local P-256 key used to emulate a cloud KMS/HSM signer."""
    def __init__(self, private_path: str, key_id: str = "p256-cloud-1"):
        self.private_path = private_path; self.key_id = key_id
        with open(private_path, "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), password=None)
    def sign(self, payload: bytes) -> dict:
        sig = self.key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return {"alg": ALG, "key_id": self.key_id, "value": base64.b64encode(sig).decode()}

class AwsKms:
    """AWS KMS asymmetric sign (ECDSA_SHA_256). Requires boto3 + AWS credentials."""
    def __init__(self, key_id: str, region: str | None = None):
        import boto3
        self.key_id = key_id; self.client = boto3.client("kms", region_name=region)
    def sign(self, payload: bytes) -> dict:
        r = self.client.sign(KeyId=self.key_id, Message=payload, MessageType="RAW",
                             SigningAlgorithm="ECDSA_SHA_256")
        return {"alg": ALG, "key_id": self.key_id,
                "value": base64.b64encode(r["Signature"]).decode()}

class GcpKms:
    """GCP Cloud KMS asymmetric sign (EC_SIGN_P256_SHA256). Requires google-cloud-kms."""
    def __init__(self, version_name: str, key_id: str = "gcp-p256-1"):
        from google.cloud import kms
        self.client = kms.KeyManagementServiceClient(); self.version_name = version_name; self.key_id = key_id
    def sign(self, payload: bytes) -> dict:
        from google.cloud import kms
        r = self.client.asymmetric_sign(request={"name": self.version_name, "digest": {"sha256": __import__("hashlib").sha256(payload).digest()}})
        return {"alg": ALG, "key_id": self.key_id, "value": base64.b64encode(r.signature).decode()}

class AzureKms:
    """Azure Key Vault key sign (ES256). Requires azure-keyvault-keys + azure-identity."""
    def __init__(self, vault_url: str, key_name: str, key_id: str = "azure-p256-1"):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys.crypto import CryptographyClient
        self.client = CryptographyClient(f"{vault_url.rstrip('/')}/keys/{key_name}", DefaultAzureCredential())
        self.key_id = key_id
    def sign(self, payload: bytes) -> dict:
        from azure.keyvault.keys.crypto import SignatureAlgorithm
        r = self.client.sign(SignatureAlgorithm.es256, payload)
        return {"alg": ALG, "key_id": self.key_id, "value": base64.b64encode(r.signature).decode()}
