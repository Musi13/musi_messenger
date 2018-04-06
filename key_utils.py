from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.exceptions import InvalidSignature
import base64


def get_public_key_hash(pub_key):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    b = digest.finalize()
    return str(base64.urlsafe_b64encode(b), encoding='utf-8')

def encode_key(file):
    return get_public_key_hash(get_key(file).public_key())
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    b = digest.finalize()
    return str(base64.urlsafe_b64encode(b), encoding='utf-8')

def get_key(file):
    key = serialization.load_pem_private_key(file.read(), None, default_backend())
    return key

def get_transfer_pub_key(file):
    key = get_key(file)
    return get_transfer_from_dual_key(key)

def get_transfer_from_dual_key(key):
    b = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return str(base64.urlsafe_b64encode(b), encoding='utf-8')

def get_pub_key_from_transfer(b64_der):
    b = base64.urlsafe_b64decode(b64_der)
    key = serialization.load_der_public_key(b, default_backend())
    return key

def get_signed_transfer(priv_key, pub_key):
    '''
    Signs the pub_key with the priv_key
    Priv should be the local key, pub is the remote
    '''
    return priv_key.sign(
        pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        asymmetric.padding.PSS(asymmetric.padding.MGF1(hashes.SHA256()), asymmetric.padding.PSS.MAX_LENGTH),
        hashes.SHA256())

# verify_key is the remote key, pub_key is the local key
def verify_signed_transfer(signature, verify_key, pub_key):
    try:
        verify_key.verify(
            signature,
            pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            asymmetric.padding.PSS(asymmetric.padding.MGF1(hashes.SHA256()), asymmetric.padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    except InvalidSignature:
        return False
    return True