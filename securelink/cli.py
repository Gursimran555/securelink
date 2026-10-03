"""
Command-line interface.

    securelink keygen  central-hospital --dir keys
    securelink fingerprint keys/central-hospital.pub
    securelink seal    --from central-hospital --to keys/satellite-clinic.pub  report.json > msg.json
    securelink open    --as satellite-clinic   --sender keys/central-hospital.pub msg.json
    securelink demo

Passphrases are read from SECURELINK_PASSPHRASE or prompted for, never
passed as arguments (those end up in shell history and process lists).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__, envelope
from .keys import (
    WeakPassphraseError,
    check_passphrase,
    fingerprint,
    generate_identity,
    load_identity,
    load_public_pem,
    save_identity,
)


def _passphrase(confirm: bool = False) -> str:
    env = os.environ.get("SECURELINK_PASSPHRASE")
    if env:
        return env
    p = getpass.getpass("Key passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != p:
        sys.exit("error: passphrases do not match")
    return p


def cmd_keygen(a: argparse.Namespace) -> None:
    p = _passphrase(confirm=True)
    try:
        check_passphrase(p)
    except WeakPassphraseError as exc:
        sys.exit(f"error: {exc}")
    ident = generate_identity(a.name, a.bits)
    path = save_identity(ident, a.dir, p)
    print(f"private key: {path} (encrypted, mode 600)")
    print(f"public key : {Path(a.dir) / (a.name + '.pub')}")
    print(f"fingerprint: {ident.fingerprint}")


def cmd_fingerprint(a: argparse.Namespace) -> None:
    print(fingerprint(load_public_pem(Path(a.pubkey).read_bytes())))


def cmd_seal(a: argparse.Namespace) -> None:
    sender = load_identity(a.sender, a.dir, _passphrase())
    recipient = load_public_pem(Path(a.to).read_bytes(), a.pin)
    data = sys.stdin.buffer.read() if a.file == "-" else Path(a.file).read_bytes()
    print(envelope.dumps(envelope.seal(sender, recipient, data)))


def cmd_open(a: argparse.Namespace) -> None:
    me = load_identity(a.me, a.dir, _passphrase())
    sender = load_public_pem(Path(a.sender).read_bytes(), a.pin)
    env = envelope.loads(Path(a.file).read_text())
    try:
        sys.stdout.buffer.write(envelope.open_envelope(me, sender, env, max_age=a.max_age))
    except envelope.EnvelopeError as exc:
        sys.exit(f"REJECTED ({type(exc).__name__}): {exc}")


def cmd_demo(_: argparse.Namespace) -> None:
    from . import demo

    demo.run()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="securelink", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=f"securelink {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create an encrypted RSA identity")
    s.add_argument("name")
    s.add_argument("--dir", default="keys")
    s.add_argument("--bits", type=int, default=3072)
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("fingerprint", help="print a public key's SHA-256 fingerprint")
    s.add_argument("pubkey")
    s.set_defaults(func=cmd_fingerprint)

    s = sub.add_parser("seal", help="encrypt + sign a file for a recipient")
    s.add_argument("file", help="file to send, or - for stdin")
    s.add_argument("--from", dest="sender", required=True, help="your identity name")
    s.add_argument("--to", required=True, help="recipient .pub file")
    s.add_argument("--pin", help="expected recipient fingerprint")
    s.add_argument("--dir", default="keys")
    s.set_defaults(func=cmd_seal)

    s = sub.add_parser("open", help="verify + decrypt an envelope")
    s.add_argument("file")
    s.add_argument("--as", dest="me", required=True, help="your identity name")
    s.add_argument("--sender", required=True, help="sender .pub file")
    s.add_argument("--pin", help="expected sender fingerprint")
    s.add_argument("--dir", default="keys")
    s.add_argument("--max-age", type=int, default=envelope.DEFAULT_MAX_AGE)
    s.set_defaults(func=cmd_open)

    s = sub.add_parser("demo", help="run the attack/defence walkthrough")
    s.set_defaults(func=cmd_demo)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
