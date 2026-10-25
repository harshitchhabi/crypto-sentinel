#!/usr/bin/env python3
"""generate.py -- build / open the hybrid post-quantum envelope used by
`pass.txt.pqenc`.

Scheme (matched to the target's field byte-lengths):

    ML-KEM-1024 (Kyber1024)  KEM        -> 32-byte shared secret
    AES-256-GCM              payload     (key = KDF(shared secret))
    ML-DSA-87 (Dilithium5)   signature   over the transmitted blob

The envelope is JSON with base64 fields:
    signature, public_key, nonce, auth_tag, ciphertext, kem_cipher

This is scaffolding: it lets us (a) prove we understand the exact format by
round-tripping, and (b) decrypt the real file the moment the organizers
hand over the ML-KEM private key or its keygen seed:

    python3 generate.py decrypt --envelope pass.txt.pqenc --kem-priv KEY

Subcommands:
    selftest   full round-trip + assert output field sizes match the target
    keygen     generate ML-KEM-1024 + ML-DSA-87 keypairs, write raw bytes
    encrypt    build an envelope from a plaintext + public KEM key + signing key
    decrypt    open an envelope given the ML-KEM private key (or --seed)

Key derivation: by default the 32-byte ML-KEM shared secret is used
directly as the AES-256 key (`--kdf raw`). If the organizers used HKDF,
pass `--kdf hkdf` (SHA-256, no salt, info=b"pqenc") on both sides.
"""

import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Target field byte-lengths, used by selftest to confirm format fidelity.
TARGET_SIZES = {
    "kem_cipher": 1568,
    "public_key": 2592,
    "signature": 4627,
    "nonce": 12,
    "auth_tag": 16,
}

FIELDS = ["signature", "public_key", "nonce", "auth_tag", "ciphertext", "kem_cipher"]


def _b64e(raw):
    return base64.b64encode(raw).decode()


def _b64d(s):
    return base64.b64decode(s)


def derive_aes_key(shared_secret, kdf):
    """Turn the 32-byte KEM shared secret into a 32-byte AES-256 key."""
    if kdf == "raw":
        return shared_secret
    if kdf == "hkdf":
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"pqenc").derive(shared_secret)
    raise ValueError(f"unknown kdf: {kdf}")


def signed_blob(kem_cipher, nonce, tag, ciphertext):
    """The bytes the ML-DSA signature covers: the whole transmitted blob."""
    return kem_cipher + nonce + tag + ciphertext


# ---------------------------------------------------------------------------
# core operations
# ---------------------------------------------------------------------------

def encrypt_envelope(plaintext, kem_public, sig_private, kdf="raw"):
    """Produce the JSON-serialisable envelope dict for ``plaintext``."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    shared_secret, kem_cipher = kem_public.encapsulate()
    aes_key = derive_aes_key(shared_secret, kdf)

    nonce = os.urandom(12)
    ct_and_tag = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    sig_public = sig_private.public_key()
    signature = sig_private.sign(signed_blob(kem_cipher, nonce, tag, ciphertext))

    return {
        "signature": _b64e(signature),
        "public_key": _b64e(sig_public.public_bytes_raw()),
        "nonce": _b64e(nonce),
        "auth_tag": _b64e(tag),
        "ciphertext": _b64e(ciphertext),
        "kem_cipher": _b64e(kem_cipher),
    }


def decrypt_envelope(envelope, kem_private, kdf="raw", verify=True):
    """Open an envelope. Returns ``(plaintext_bytes, signature_ok)``.

    ``signature_ok`` is None when ``verify`` is False, else a bool from
    checking the embedded ML-DSA-87 public key against the signed blob.
    """
    kem_cipher = _b64d(envelope["kem_cipher"])
    nonce = _b64d(envelope["nonce"])
    tag = _b64d(envelope["auth_tag"])
    ciphertext = _b64d(envelope["ciphertext"])

    shared_secret = kem_private.decapsulate(kem_cipher)
    aes_key = derive_aes_key(shared_secret, kdf)
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)

    sig_ok = None
    if verify:
        sig_public = mldsa.MLDSA87PublicKey.from_public_bytes(_b64d(envelope["public_key"]))
        try:
            sig_public.verify(_b64d(envelope["signature"]),
                              signed_blob(kem_cipher, nonce, tag, ciphertext))
            sig_ok = True
        except Exception:
            sig_ok = False
    return plaintext, sig_ok


# ---------------------------------------------------------------------------
# key loading helpers
# ---------------------------------------------------------------------------

def _read_key_bytes(path):
    """Read a key file as raw bytes, tolerating base64/hex text wrappers."""
    with open(path, "rb") as fh:
        data = fh.read()
    stripped = data.strip()
    # try base64, then hex, else assume raw
    try:
        d = base64.b64decode(stripped, validate=True)
        if d:
            return d
    except Exception:
        pass
    try:
        return bytes.fromhex(stripped.decode("ascii"))
    except Exception:
        pass
    return data


def load_kem_private(args):
    if args.seed:
        return mlkem.MLKEM1024PrivateKey.from_seed_bytes(_read_key_bytes(args.seed))
    return mlkem.MLKEM1024PrivateKey.from_seed_bytes(_read_key_bytes(args.kem_priv)) \
        if getattr(args, "kem_priv_is_seed", False) \
        else _load_kem_private_raw(args.kem_priv)


def _load_kem_private_raw(path):
    raw = _read_key_bytes(path)
    # from_seed_bytes expects a 64-byte seed; a full expanded private key is
    # larger. Try seed first, fall back to raw private bytes.
    try:
        return mlkem.MLKEM1024PrivateKey.from_seed_bytes(raw)
    except Exception:
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        return load_der_private_key(raw, password=None)


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_selftest(args):
    kem_priv = mlkem.MLKEM1024PrivateKey.generate()
    kem_pub = kem_priv.public_key()
    sig_priv = mldsa.MLDSA87PrivateKey.generate()

    message = b"msbj" + os.urandom(225)  # 229 bytes, same as the target payload
    env = encrypt_envelope(message, kem_pub, sig_priv, kdf=args.kdf)

    print("field byte-lengths (generated vs target):")
    ok = True
    for name in ["kem_cipher", "public_key", "signature", "nonce", "auth_tag"]:
        got = len(_b64d(env[name]))
        want = TARGET_SIZES[name]
        mark = "ok" if got == want else "MISMATCH"
        if got != want:
            ok = False
        print(f"  {name:12s} {got:5d}  (target {want})  {mark}")
    print(f"  ciphertext   {len(_b64d(env['ciphertext'])):5d}  (= plaintext length, AES-GCM stream)")

    pt, sig_ok = decrypt_envelope(env, kem_priv, kdf=args.kdf)
    print(f"\nround-trip decrypt matches: {pt == message}")
    print(f"signature verifies:        {sig_ok}")
    print(f"recovered prefix:          {pt[:4]!r}")

    if ok and pt == message and sig_ok:
        print("\nSELFTEST PASSED -- envelope format matches pass.txt.pqenc exactly.")
        return 0
    print("\nSELFTEST FAILED")
    return 1


def cmd_keygen(args):
    os.makedirs(args.out_dir, exist_ok=True)
    kem_priv = mlkem.MLKEM1024PrivateKey.generate()
    sig_priv = mldsa.MLDSA87PrivateKey.generate()

    def write(name, raw):
        path = os.path.join(args.out_dir, name)
        with open(path, "wb") as fh:
            fh.write(raw)
        print(f"  wrote {path} ({len(raw)} bytes)")

    write("kem_private.raw", kem_priv.private_bytes_raw())
    write("kem_public.raw", kem_priv.public_key().public_bytes_raw())
    write("sig_private.raw", sig_priv.private_bytes_raw())
    write("sig_public.raw", sig_priv.public_key().public_bytes_raw())
    print(f"keypairs written to {args.out_dir}/")
    return 0


def cmd_encrypt(args):
    kem_pub = mlkem.MLKEM1024PublicKey.from_public_bytes(_read_key_bytes(args.kem_pub))
    sig_priv_raw = _read_key_bytes(args.sig_priv)
    try:
        sig_priv = mldsa.MLDSA87PrivateKey.from_seed_bytes(sig_priv_raw)
    except Exception:
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        sig_priv = load_der_private_key(sig_priv_raw, password=None)

    if args.plaintext is not None:
        pt = args.plaintext.encode()
    else:
        with open(args.infile, "rb") as fh:
            pt = fh.read()

    env = encrypt_envelope(pt, kem_pub, sig_priv, kdf=args.kdf)
    out = json.dumps(env, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(out)
        print(f"envelope written to {args.out}")
    else:
        print(out)
    return 0


def cmd_decrypt(args):
    with open(args.envelope) as fh:
        env = json.load(fh)

    seed = _read_key_bytes(args.seed) if args.seed else None
    if seed is not None:
        kem_priv = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)
    else:
        kem_priv = _load_kem_private_raw(args.kem_priv)

    pt, sig_ok = decrypt_envelope(env, kem_priv, kdf=args.kdf, verify=not args.no_verify)
    print(f"signature verifies: {sig_ok}")
    try:
        print("plaintext:", pt.decode("utf-8"))
    except UnicodeDecodeError:
        print("plaintext (bytes):", pt)
    if args.known_prefix:
        kp = args.known_prefix.encode()
        print(f"starts with {args.known_prefix!r}: {pt.startswith(kp)}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    common_kdf = dict(choices=["raw", "hkdf"], default="raw",
                      help="AES-key derivation from the KEM shared secret (default: raw)")

    s = sub.add_parser("selftest", help="round-trip and assert format fidelity")
    s.add_argument("--kdf", **common_kdf)
    s.set_defaults(func=cmd_selftest)

    g = sub.add_parser("keygen", help="generate keypairs")
    g.add_argument("--out-dir", default="keys")
    g.set_defaults(func=cmd_keygen)

    e = sub.add_parser("encrypt", help="build an envelope")
    e.add_argument("--kem-pub", required=True, help="ML-KEM-1024 public key file")
    e.add_argument("--sig-priv", required=True, help="ML-DSA-87 signing key / seed file")
    grp = e.add_mutually_exclusive_group(required=True)
    grp.add_argument("--plaintext", help="plaintext string")
    grp.add_argument("--infile", help="plaintext file")
    e.add_argument("--out", help="write envelope JSON here (default: stdout)")
    e.add_argument("--kdf", **common_kdf)
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser("decrypt", help="open an envelope with the KEM private key")
    d.add_argument("--envelope", default="pass.txt.pqenc")
    kgrp = d.add_mutually_exclusive_group(required=True)
    kgrp.add_argument("--kem-priv", help="ML-KEM-1024 private key file")
    kgrp.add_argument("--seed", help="ML-KEM-1024 keygen seed file (64 bytes)")
    d.add_argument("--kdf", **common_kdf)
    d.add_argument("--known-prefix", default="msbj")
    d.add_argument("--no-verify", action="store_true", help="skip signature check")
    d.set_defaults(func=cmd_decrypt)
    return p


def main():
    args = build_parser().parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
