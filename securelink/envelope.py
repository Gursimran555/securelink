"""
Secure envelope: authenticated hybrid encryption between two identities.

    sender                                            recipient
    ------                                            ---------
    K   = random AES-256 key (fresh per message)
    hdr = {version, sender, recipient fingerprint, timestamp, msg_id}
    C   = AES-256-GCM(K, nonce, plaintext, aad=hdr)
    W   = RSA-OAEP(recipient_pub, K)
    S   = RSA-PSS(sender_priv, hdr || W || nonce || C)
                     ---- {hdr, W, nonce, C, S} ---->
                                                      1. verify S with pinned sender key
                                                      2. check recipient fingerprint
                                                      3. check freshness + replay cache
                                                      4. K = RSA-OAEP-decrypt(W)
                                                      5. plaintext = AES-GCM-decrypt(C, aad=hdr)

Why this shape:
* RSA can only encrypt ~318 bytes with a 3072-bit key and is slow, so it only
  wraps a small symmetric key. AES-GCM carries the payload.
* GCM authenticates the ciphertext and binds the header through AAD.
* The outer signature proves *who* sent it (GCM alone can't, because anyone
  holding the recipient's public key could make a valid-looking envelope).
* The signature covers the wrapped key, so an attacker cannot strip it and
  re-sign the same ciphertext as themselves.
* msg_id + timestamp + a replay cache stop an attacker re-sending a captured
  message (e.g. a duplicate medication order).
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import primitives
from .keys import Identity, fingerprint

VERSION = 1
ALGORITHM = "RSA-OAEP-SHA256+AES-256-GCM+RSA-PSS-SHA256"
DEFAULT_MAX_AGE = 300  # seconds an envelope stays valid
CLOCK_SKEW = 30  # seconds of tolerance for a sender clock that runs ahead


class EnvelopeError(Exception):
    """Base class: the envelope must be rejected."""


class BadSignature(EnvelopeError):
    pass


class WrongRecipient(EnvelopeError):
    pass


class Expired(EnvelopeError):
    pass


class Replayed(EnvelopeError):
    pass


class DecryptionFailed(EnvelopeError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON so sender and receiver sign/verify identical bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _signed_part(env: dict) -> bytes:
    return _canonical({k: env[k] for k in ("header", "wrapped_key", "nonce", "ciphertext")})


@dataclass
class ReplayCache:
    """Remembers message IDs until they expire. Use one cache per recipient.

    In production this would be shared storage (Redis, a DB table) so that
    restarts and multiple workers can't be used to slip a replay through.
    """

    max_age: int = DEFAULT_MAX_AGE
    _seen: dict[str, float] = field(default_factory=dict)

    def check_and_add(self, msg_id: str, now: float) -> None:
        # Drop expired entries so memory stays bounded.
        self._seen = {m: t for m, t in self._seen.items() if now - t <= self.max_age + CLOCK_SKEW}
        if msg_id in self._seen:
            raise Replayed(f"message {msg_id} was already accepted")
        self._seen[msg_id] = now


def seal(
    sender: Identity,
    recipient_public_key: rsa.RSAPublicKey,
    plaintext: bytes,
    *,
    now: float | None = None,
) -> dict:
    """Encrypt and sign ``plaintext`` for one recipient. Returns a JSON-safe dict."""
    header = {
        "v": VERSION,
        "alg": ALGORITHM,
        "sender": sender.name,
        "recipient_fp": fingerprint(recipient_public_key),
        "ts": int(now if now is not None else time.time()),
        "msg_id": _b64(os.urandom(16)),
    }
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # 96-bit nonce; key is single-use, so no reuse risk
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, _canonical(header))

    env = {
        "header": header,
        "wrapped_key": _b64(primitives.rsa_encrypt(recipient_public_key, session_key)),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    env["signature"] = _b64(primitives.sign(sender.private_key, _signed_part(env)))
    return env


def open_envelope(
    recipient: Identity,
    sender_public_key: rsa.RSAPublicKey,
    env: dict,
    *,
    replay_cache: ReplayCache | None = None,
    max_age: int = DEFAULT_MAX_AGE,
    now: float | None = None,
) -> bytes:
    """Verify and decrypt. Raises an EnvelopeError subclass on any problem.

    The order matters: authenticate first, then do the expensive private-key
    operation. That way an unauthenticated attacker can't use us as a
    decryption oracle.
    """
    try:
        header = env["header"]
        signature = _unb64(env["signature"])
        signed = _signed_part(env)
    except (KeyError, TypeError, ValueError) as exc:
        raise EnvelopeError(f"malformed envelope: {exc}") from None

    if header.get("v") != VERSION or header.get("alg") != ALGORITHM:
        raise EnvelopeError("unsupported version or algorithm")  # no downgrade

    if not primitives.verify(sender_public_key, signature, signed):
        raise BadSignature("signature does not match the pinned sender key")

    if header["recipient_fp"] != recipient.fingerprint:
        raise WrongRecipient("envelope was sealed for a different key")

    now = now if now is not None else time.time()
    age = now - header["ts"]
    if age > max_age or age < -CLOCK_SKEW:
        raise Expired(f"envelope age {age:.0f}s is outside the {max_age}s window")

    if replay_cache is not None:
        replay_cache.check_and_add(header["msg_id"], now)

    try:
        session_key = primitives.rsa_decrypt(recipient.private_key, _unb64(env["wrapped_key"]))
        return AESGCM(session_key).decrypt(
            _unb64(env["nonce"]), _unb64(env["ciphertext"]), _canonical(header)
        )
    except (InvalidTag, ValueError) as exc:
        raise DecryptionFailed("could not decrypt envelope") from exc


def dumps(env: dict) -> str:
    return json.dumps(env, indent=2)


def loads(text: str) -> dict:
    return json.loads(text)
