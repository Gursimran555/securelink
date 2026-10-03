"""
Thin, safe-by-default wrappers around the RSA operations the protocol uses.

* Encryption uses RSA-OAEP with SHA-256 (never textbook RSA or PKCS#1 v1.5,
  which are malleable or open to padding-oracle attacks).
* Signatures use RSA-PSS with SHA-256 and maximum salt length.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def oaep_max_plaintext(public_key: rsa.RSAPublicKey) -> int:
    """Largest message RSA-OAEP-SHA256 can encrypt: k - 2*hLen - 2 bytes."""
    return public_key.key_size // 8 - 2 * hashes.SHA256.digest_size - 2


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    limit = oaep_max_plaintext(public_key)
    if len(plaintext) > limit:
        raise ValueError(
            f"{len(plaintext)} bytes is over the RSA-OAEP limit of {limit} bytes; "
            "use a hybrid envelope (securelink.envelope) for bulk data"
        )
    return public_key.encrypt(plaintext, _OAEP)


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, _OAEP)


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Hash-then-sign. Hashing is what stops the existential forgeries
    and multiplicative tricks that work against raw RSA signatures."""
    return private_key.sign(data, _PSS, hashes.SHA256())


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
