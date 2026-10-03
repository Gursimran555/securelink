"""
Identity keys: RSA key generation, encrypted storage and fingerprints.

Each site (e.g. a hospital or clinic) owns one long-term RSA identity key.
The private half never leaves the site and is stored encrypted at rest; the
public half is shared, and peers pin it by its SHA-256 fingerprint, which is
compared over a separate trusted channel such as a phone call.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

#: 3072-bit RSA gives ~128-bit security, which is what NIST SP 800-57 recommends past 2030.
DEFAULT_KEY_SIZE = 3072
#: Smallest key we accept for keys loaded from disk or received from a peer.
MIN_KEY_SIZE = 2048
#: Fermat prime F4: the standard, safe public exponent.
PUBLIC_EXPONENT = 65537


class WeakPassphraseError(ValueError):
    """The passphrase that would protect a private key is too weak."""


class WeakKeyError(ValueError):
    """A key is smaller than MIN_KEY_SIZE."""


@dataclass(frozen=True)
class Identity:
    """A named site and its RSA key pair."""

    name: str
    private_key: rsa.RSAPrivateKey

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)


def generate_identity(name: str, key_size: int = DEFAULT_KEY_SIZE) -> Identity:
    """Create a fresh RSA identity for ``name``."""
    if key_size < MIN_KEY_SIZE:
        raise WeakKeyError(f"key size {key_size} < {MIN_KEY_SIZE}")
    key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)
    return Identity(name=name, private_key=key)


def check_passphrase(passphrase: str) -> None:
    """Reject passphrases that would make the encrypted key file easy to brute-force.

    Policy: at least 12 characters, with three of these four classes:
    lowercase, uppercase, digits, symbols.
    """
    if len(passphrase) < 12:
        raise WeakPassphraseError("passphrase must be at least 12 characters")
    classes = sum(
        bool(re.search(p, passphrase)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    if classes < 3:
        raise WeakPassphraseError(
            "passphrase needs 3 of: lowercase, uppercase, digits, symbols"
        )


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo, shown as colon-separated hex pairs."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def public_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_pem(data: bytes, expected_fingerprint: str | None = None) -> rsa.RSAPublicKey:
    """Load a peer's public key and optionally pin it to a known fingerprint."""
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("expected an RSA public key")
    if key.key_size < MIN_KEY_SIZE:
        raise WeakKeyError(f"peer key is only {key.key_size} bits")
    if expected_fingerprint is not None:
        if fingerprint(key).replace(":", "") != expected_fingerprint.replace(":", "").upper():
            raise ValueError("public key fingerprint does not match the pinned value")
    return key


def save_identity(identity: Identity, directory: str | os.PathLike, passphrase: str) -> Path:
    """Write ``<name>.key`` (encrypted, owner-only) and ``<name>.pub`` (shareable).

    The private key is serialized as PKCS#8 and encrypted with the library's
    best available scheme (AES-256-CBC, key derived from the passphrase with a
    salted, iterated KDF).
    """
    check_passphrase(passphrase)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    private_path = directory / f"{identity.name}.key"
    encrypted = identity.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    )
    # Create the file with 0600 from the start, so it is never briefly world-readable.
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(encrypted)
    os.chmod(private_path, 0o600)  # also tighten a pre-existing file (no-op on Windows ACLs)

    (directory / f"{identity.name}.pub").write_bytes(public_pem(identity.public_key))
    return private_path


def load_identity(name: str, directory: str | os.PathLike, passphrase: str) -> Identity:
    """Decrypt and load ``<name>.key``. A wrong passphrase raises ``ValueError``."""
    data = (Path(directory) / f"{name}.key").read_bytes()
    key = serialization.load_pem_private_key(data, password=passphrase.encode())
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("expected an RSA private key")
    if key.key_size < MIN_KEY_SIZE:
        raise WeakKeyError(f"stored key is only {key.key_size} bits")
    return Identity(name=name, private_key=key)
