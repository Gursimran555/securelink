import copy
import os
import stat
import sys
import time

import pytest

from securelink import envelope, primitives
from securelink.keys import (
    WeakKeyError,
    WeakPassphraseError,
    check_passphrase,
    generate_identity,
    load_identity,
    load_public_pem,
    public_pem,
    save_identity,
)
from securelink.kex import HandshakeError, Party

PASS = "Correct-Horse-42!"


@pytest.fixture(scope="session")
def ids():
    return {n: generate_identity(n) for n in ("alice", "bob", "mallory")}


# ---------- keys ----------

def test_key_size_and_fingerprint_format(ids):
    a = ids["alice"]
    assert a.private_key.key_size == 3072
    assert len(a.fingerprint.split(":")) == 32


def test_rejects_small_keys():
    with pytest.raises(WeakKeyError):
        generate_identity("x", 1024)


@pytest.mark.parametrize("p", ["short1!A", "alllowercaseletters", "NoDigitsOrSymbols"])
def test_weak_passphrases_rejected(p):
    with pytest.raises(WeakPassphraseError):
        check_passphrase(p)


def test_save_and_load_roundtrip(ids, tmp_path):
    path = save_identity(ids["alice"], tmp_path, PASS)
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert b"ENCRYPTED" in path.read_bytes()
    loaded = load_identity("alice", tmp_path, PASS)
    assert loaded.fingerprint == ids["alice"].fingerprint


def test_wrong_passphrase_fails(ids, tmp_path):
    save_identity(ids["alice"], tmp_path, PASS)
    with pytest.raises(ValueError):
        load_identity("alice", tmp_path, "Wrong-Passphrase-1")


def test_fingerprint_pinning(ids):
    pem = public_pem(ids["bob"].public_key)
    assert load_public_pem(pem, ids["bob"].fingerprint)
    with pytest.raises(ValueError):
        load_public_pem(pem, ids["mallory"].fingerprint)


# ---------- primitives ----------

def test_rsa_oaep_roundtrip_and_limit(ids):
    bob = ids["bob"]
    assert primitives.rsa_decrypt(bob.private_key, primitives.rsa_encrypt(bob.public_key, b"hi")) == b"hi"
    with pytest.raises(ValueError):
        primitives.rsa_encrypt(bob.public_key, b"x" * 400)


def test_oaep_is_randomized(ids):
    pub = ids["bob"].public_key
    assert primitives.rsa_encrypt(pub, b"same") != primitives.rsa_encrypt(pub, b"same")


def test_signature_detects_tampering(ids):
    a = ids["alice"]
    sig = primitives.sign(a.private_key, b"result=6.5")
    assert primitives.verify(a.public_key, sig, b"result=6.5")
    assert not primitives.verify(a.public_key, sig, b"result=16.5")
    assert not primitives.verify(ids["mallory"].public_key, sig, b"result=6.5")


# ---------- envelope ----------

@pytest.fixture
def sealed(ids):
    return envelope.seal(ids["alice"], ids["bob"].public_key, b"patient record")


def test_envelope_roundtrip(ids, sealed):
    assert envelope.open_envelope(ids["bob"], ids["alice"].public_key, sealed) == b"patient record"


def test_envelope_survives_json(ids, sealed):
    env = envelope.loads(envelope.dumps(sealed))
    assert envelope.open_envelope(ids["bob"], ids["alice"].public_key, env) == b"patient record"


def test_large_payload(ids):
    data = os.urandom(2 * 1024 * 1024)
    env = envelope.seal(ids["alice"], ids["bob"].public_key, data)
    assert envelope.open_envelope(ids["bob"], ids["alice"].public_key, env) == data


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "wrapped_key"])
def test_tampered_fields_rejected(ids, sealed, field):
    env = copy.deepcopy(sealed)
    raw = bytearray(envelope._unb64(env[field]))
    raw[0] ^= 1
    env[field] = envelope._b64(bytes(raw))
    with pytest.raises(envelope.BadSignature):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, env)


def test_tampered_header_rejected(ids, sealed):
    env = copy.deepcopy(sealed)
    env["header"]["ts"] += 1
    with pytest.raises(envelope.BadSignature):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, env)


def test_forged_sender_rejected(ids):
    env = envelope.seal(ids["mallory"], ids["bob"].public_key, b"fake")
    env["header"]["sender"] = "alice"
    with pytest.raises(envelope.BadSignature):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, env)


def test_wrong_recipient_rejected(ids, sealed):
    with pytest.raises(envelope.WrongRecipient):
        envelope.open_envelope(ids["mallory"], ids["alice"].public_key, sealed)


def test_replay_rejected(ids, sealed):
    cache = envelope.ReplayCache()
    envelope.open_envelope(ids["bob"], ids["alice"].public_key, sealed, replay_cache=cache)
    with pytest.raises(envelope.Replayed):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, sealed, replay_cache=cache)


@pytest.mark.parametrize("offset", [-3600, +3600])
def test_stale_or_future_rejected(ids, offset):
    env = envelope.seal(ids["alice"], ids["bob"].public_key, b"x", now=time.time() + offset)
    with pytest.raises(envelope.Expired):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, env)


def test_downgrade_rejected(ids, sealed):
    env = copy.deepcopy(sealed)
    env["header"]["alg"] = "RSA-PKCS1v15"
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, env)


def test_malformed_rejected(ids):
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(ids["bob"], ids["alice"].public_key, {"header": {}})


# ---------- key exchange ----------

def test_authenticated_kex_agrees(ids):
    a, b = Party(ids["alice"]), Party(ids["bob"])
    ka = a.derive(b.hello("alice"), ids["bob"].public_key)
    kb = b.derive(a.hello("bob"), ids["alice"].public_key)
    assert ka == kb and len(ka) == 32


def test_fresh_keys_each_session(ids):
    def session():
        a, b = Party(ids["alice"]), Party(ids["bob"])
        return a.derive(b.hello("alice"), ids["bob"].public_key)
    assert session() != session()


def test_unauthenticated_kex_is_vulnerable_to_mitm(ids):
    a, m = Party(ids["alice"]), Party(ids["mallory"])
    fake = m.hello("alice", authenticated=False)
    fake.sender = "bob"
    assert a.derive(fake) == m.derive(a.hello("bob", authenticated=False))


def test_authenticated_kex_blocks_mitm(ids):
    a, m = Party(ids["alice"]), Party(ids["mallory"])
    fake = m.hello("alice")
    fake.sender = "bob"
    with pytest.raises(HandshakeError):
        a.derive(fake, ids["bob"].public_key)


def test_unsigned_hello_rejected_when_auth_required(ids):
    a, b = Party(ids["alice"]), Party(ids["bob"])
    with pytest.raises(HandshakeError):
        a.derive(b.hello("alice", authenticated=False), ids["bob"].public_key)


def test_hello_bound_to_intended_peer(ids):
    # A hello signed for mallory cannot be relayed to alice.
    b = Party(ids["bob"])
    relayed = b.hello("mallory")
    with pytest.raises(HandshakeError):
        Party(ids["alice"]).derive(relayed, ids["bob"].public_key)


# ---------- CLI ----------

def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    from securelink.cli import main

    monkeypatch.setenv("SECURELINK_PASSPHRASE", PASS)
    kd = str(tmp_path / "keys")
    main(["keygen", "alice", "--dir", kd, "--bits", "2048"])
    main(["keygen", "bob", "--dir", kd, "--bits", "2048"])
    capsys.readouterr()

    msg = tmp_path / "msg.txt"
    msg.write_bytes(b"lab result: 6.5")
    main(["seal", str(msg), "--from", "alice", "--to", f"{kd}/bob.pub", "--dir", kd])
    env_file = tmp_path / "msg.json"
    env_file.write_text(capsys.readouterr().out)

    main(["open", str(env_file), "--as", "bob", "--sender", f"{kd}/alice.pub", "--dir", kd])
    assert capsys.readouterr().out == "lab result: 6.5"
