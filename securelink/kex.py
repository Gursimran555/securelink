"""
Ephemeral key agreement with X25519 and the man-in-the-middle problem.

Plain Diffie-Hellman gives two parties a shared secret over a public channel,
but it does not tell either side *who* is on the other end. An active attacker
(Mallory) can sit in the middle, run one exchange with each side, and read
or change everything while both sides believe they are secure.

The fix is to authenticate the exchange: each side signs its ephemeral public
key, together with both identities, using its long-term RSA identity key.
Mallory can swap the ephemeral key but cannot forge the signature.

Each session uses a fresh ephemeral key that is thrown away afterwards, so a
later compromise of the RSA identity keys does not expose past sessions
(forward secrecy). The RSA-wrapped envelope does not have that property.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import primitives
from .keys import Identity

INFO = b"securelink/v1 session key"


class HandshakeError(Exception):
    """The peer's ephemeral key could not be authenticated."""


def _raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class Hello:
    """What one side sends: its name, ephemeral X25519 key and (optionally) a signature."""

    sender: str
    ephemeral: bytes
    signature: bytes | None = None


class Party:
    """One side of a handshake. A new Party (and ephemeral key) per session."""

    def __init__(self, identity: Identity):
        self.identity = identity
        self._eph = X25519PrivateKey.generate()

    @property
    def ephemeral_public(self) -> bytes:
        return _raw(self._eph.public_key())

    def _transcript(self, sender: str, receiver: str, eph: bytes) -> bytes:
        # Binding both names stops Mallory replaying A's signed hello to a third party.
        return b"|".join([b"securelink-hello-v1", sender.encode(), receiver.encode(), eph])

    def hello(self, peer_name: str, authenticated: bool = True) -> Hello:
        sig = None
        if authenticated:
            sig = primitives.sign(
                self.identity.private_key,
                self._transcript(self.identity.name, peer_name, self.ephemeral_public),
            )
        return Hello(self.identity.name, self.ephemeral_public, sig)

    def derive(
        self,
        peer: Hello,
        peer_identity_key: rsa.RSAPublicKey | None = None,
    ) -> bytes:
        """Return a 32-byte session key. If ``peer_identity_key`` is given, the
        peer's hello must carry a valid signature from it."""
        if peer_identity_key is not None:
            data = self._transcript(peer.sender, self.identity.name, peer.ephemeral)
            if peer.signature is None or not primitives.verify(
                peer_identity_key, peer.signature, data
            ):
                raise HandshakeError(f"hello claiming to be {peer.sender!r} is not authentic")

        shared = self._eph.exchange(X25519PublicKey.from_public_bytes(peer.ephemeral))
        # Salt with both ephemerals in a fixed order so both sides get the same key.
        salt = b"".join(sorted([self.ephemeral_public, peer.ephemeral]))
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)
