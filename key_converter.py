from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import base64


def encode_key(file):
    key = serialization.load_pem_private_key(file.read(), None, default_backend())
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    b = digest.finalize()
    return str(base64.urlsafe_b64encode(b), encoding='utf-8')
