"""
End-to-end walkthrough: two healthcare sites exchange patient data while an
attacker tries five different things to break it. Run with `securelink demo`.
"""

from __future__ import annotations

import copy
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import envelope, primitives
from .keys import generate_identity
from .kex import HandshakeError, Party

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
if os.environ.get("NO_COLOR"):
    GREEN = RED = DIM = BOLD = RESET = ""


def step(title: str) -> None:
    print(f"\n{BOLD}== {title} =={RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}[ok]{RESET} {msg}")


def blocked(msg: str) -> None:
    print(f"  {RED}[blocked]{RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {DIM}{msg}{RESET}")


def _expect_reject(label: str, fn) -> None:
    try:
        fn()
    except (envelope.EnvelopeError, HandshakeError) as exc:
        blocked(f"{label}: {type(exc).__name__}: {exc}")
    else:
        raise AssertionError(f"{label} was NOT rejected")


def run() -> None:
    step("1. Identities")
    t = time.perf_counter()
    hospital = generate_identity("central-hospital")
    clinic = generate_identity("satellite-clinic")
    mallory = generate_identity("mallory")
    info(f"3 x RSA-3072 keys generated in {time.perf_counter() - t:.2f}s")
    ok(f"central-hospital  {hospital.fingerprint[:47]}...")
    ok(f"satellite-clinic  {clinic.fingerprint[:47]}...")
    info("Fingerprints are compared out-of-band (phone call) before trusting a key.")

    step("2. Sealed envelope: hospital -> clinic")
    record = (
        b'{"patient":"MRN-000417","test":"HbA1c","result":6.5,"unit":"%",'
        b'"note":"Within target. Continue current plan."}'
    )
    env = envelope.seal(hospital, clinic.public_key, record)
    info(f"plaintext {len(record)} B -> envelope {len(envelope.dumps(env))} B (JSON)")
    cache = envelope.ReplayCache()
    out = envelope.open_envelope(clinic, hospital.public_key, env, replay_cache=cache)
    assert out == record
    ok("clinic verified the signature and decrypted the record")

    step("3. Attacks on the envelope")
    tampered = copy.deepcopy(env)
    ct = bytearray(envelope._unb64(tampered["ciphertext"]))
    ct[40] ^= 0x01  # flip one bit, e.g. try to turn 6.5 into something else
    tampered["ciphertext"] = envelope._b64(bytes(ct))
    _expect_reject("bit-flip in ciphertext", lambda: envelope.open_envelope(
        clinic, hospital.public_key, tampered))

    forged = envelope.seal(mallory, clinic.public_key, b'{"result":16.5}')
    forged["header"]["sender"] = "central-hospital"
    _expect_reject("mallory impersonates hospital", lambda: envelope.open_envelope(
        clinic, hospital.public_key, forged))

    _expect_reject("replay of captured envelope", lambda: envelope.open_envelope(
        clinic, hospital.public_key, env, replay_cache=cache))

    old = envelope.seal(hospital, clinic.public_key, record, now=time.time() - 3600)
    _expect_reject("one-hour-old envelope", lambda: envelope.open_envelope(
        clinic, hospital.public_key, old))

    _expect_reject("mallory opens envelope meant for clinic", lambda: envelope.open_envelope(
        mallory, hospital.public_key, env))

    step("4. Why hybrid? RSA alone vs RSA + AES-GCM")
    limit = primitives.oaep_max_plaintext(clinic.public_key)
    info(f"RSA-3072 OAEP can encrypt at most {limit} bytes per operation")
    data = os.urandom(512 * 1024)
    chunks = [data[i : i + limit] for i in range(0, len(data), limit)]
    t = time.perf_counter()
    for c in chunks:
        primitives.rsa_encrypt(clinic.public_key, c)
    rsa_enc = time.perf_counter() - t
    rsa_dec_one = time.perf_counter()
    primitives.rsa_decrypt(clinic.private_key, primitives.rsa_encrypt(clinic.public_key, chunks[0]))
    rsa_dec_one = time.perf_counter() - rsa_dec_one
    key = AESGCM.generate_key(bit_length=256)
    t = time.perf_counter()
    AESGCM(key).encrypt(os.urandom(12), data, None)
    aes = time.perf_counter() - t
    ok(f"512 KB with RSA only: {len(chunks)} operations, {rsa_enc * 1000:.0f} ms to encrypt, "
       f"~{rsa_dec_one * len(chunks) * 1000:.0f} ms to decrypt")
    ok(f"512 KB with AES-256-GCM: {aes * 1000:.2f} ms (+1 RSA op to wrap the key)")

    step("5. Key exchange: X25519 with and without authentication")
    a, b = Party(hospital), Party(clinic)
    ka = a.derive(b.hello("central-hospital", authenticated=False))
    kb = b.derive(a.hello("satellite-clinic", authenticated=False))
    assert ka == kb
    ok(f"unauthenticated X25519: both sides derived {ka.hex()[:16]}...")

    info("Now Mallory intercepts and substitutes her own ephemeral keys:")
    a, b = Party(hospital), Party(clinic)
    m_to_a, m_to_b = Party(mallory), Party(mallory)
    fake_b = m_to_a.hello("central-hospital", authenticated=False)
    fake_b.sender = "satellite-clinic"
    fake_a = m_to_b.hello("satellite-clinic", authenticated=False)
    fake_a.sender = "central-hospital"
    ka, kb = a.derive(fake_b), b.derive(fake_a)
    km_a = m_to_a.derive(a.hello("satellite-clinic", authenticated=False))
    km_b = m_to_b.derive(b.hello("central-hospital", authenticated=False))
    assert ka == km_a and kb == km_b and ka != kb
    print(f"  {RED}[MITM]{RESET} hospital key {ka.hex()[:12]}... == mallory's; "
          f"clinic key {kb.hex()[:12]}... == mallory's. Mallory reads everything.")

    info("Same attack, but each hello is signed with the RSA identity key:")
    a, b = Party(hospital), Party(clinic)
    fake_b = Party(mallory).hello("central-hospital")
    fake_b.sender = "satellite-clinic"
    _expect_reject("mallory's substituted key", lambda: a.derive(fake_b, clinic.public_key))
    ka = a.derive(b.hello("central-hospital"), clinic.public_key)
    kb = b.derive(a.hello("satellite-clinic"), hospital.public_key)
    assert ka == kb
    ok(f"authenticated X25519: genuine peers agree on {ka.hex()[:16]}..., forward secret")

    print(f"\n{GREEN}{BOLD}All checks passed.{RESET}")


if __name__ == "__main__":
    run()
