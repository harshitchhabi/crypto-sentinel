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
pass `--kdf hkdf` (SHA-256, no salt, info=b"pqenc") or `--kdf auto` on decrypt.
"""

import argparse
import base64
import json
import os
import sys

from crypto_engine import pqc

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
        return pqc.hkdf_sha256(shared_secret, length=32, salt=None, info=b"pqenc")
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
    ciphertext, tag = pqc.aes_gcm_encrypt(aes_key, nonce, plaintext, aad=None)

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
    checking the embedded ML-DSA-87 public key against the signed blob
    (or decrypted plaintext if the sender signed the plaintext before encryption).
    """
    kem_cipher = _b64d(envelope["kem_cipher"])
    nonce = _b64d(envelope["nonce"])
    tag = _b64d(envelope["auth_tag"])
    ciphertext = _b64d(envelope["ciphertext"])

    sig_ok = None
    sig_public = None
    sig_bytes = None
    if verify:
        sig_public = pqc.MLDSA87PublicKey.from_public_bytes(_b64d(envelope["public_key"]))
        sig_bytes = _b64d(envelope["signature"])
        try:
            sig_public.verify(sig_bytes, signed_blob(kem_cipher, nonce, tag, ciphertext))
            sig_ok = True
        except Exception:
            sig_ok = False

    shared_secret = kem_private.decapsulate(kem_cipher)
    kdf_modes = ["raw", "hkdf"] if kdf == "auto" else [kdf]
    plaintext = None
    for mode in kdf_modes:
        aes_key = derive_aes_key(shared_secret, mode)
        plaintext = pqc.aes_gcm_decrypt(ciphertext, aes_key, nonce, tag, aad=None)
        if plaintext is not None:
            break

    if plaintext is None:
        raise ValueError("AES-GCM authentication failed (wrong key or KDF mode)")

    # If envelope signature did not match the outer ciphertext blob, check
    # whether the sender signed the plaintext directly.
    if verify and not sig_ok and sig_public is not None:
        try:
            sig_public.verify(sig_bytes, plaintext)
            sig_ok = True
        except Exception:
            pass

    return plaintext, sig_ok


# ---------------------------------------------------------------------------
# key loading helpers
# ---------------------------------------------------------------------------

def _read_key_bytes(path):
    """Read a key file safely (raw binary, hex text, or base64 text)."""
    return pqc.read_key_bytes(path)


def _load_kem_private_raw(path):
    """Load an ML-KEM-1024 private key from a 64-byte seed, 3168-byte raw key, or DER."""
    raw = _read_key_bytes(path)
    return pqc.MLKEM1024PrivateKey.from_private_bytes(raw)


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_selftest(args):
    kem_priv = pqc.MLKEM1024PrivateKey.generate()
    kem_pub = kem_priv.public_key()
    sig_priv = pqc.MLDSA87PrivateKey.generate()

    message = b"msbj" + os.urandom(225)  # 229 bytes, same as the target payload
    kdf_mode = "raw" if args.kdf == "auto" else args.kdf
    env = encrypt_envelope(message, kem_pub, sig_priv, kdf=kdf_mode)

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
    kem_priv = pqc.MLKEM1024PrivateKey.generate()
    sig_priv = pqc.MLDSA87PrivateKey.generate()

    def write(name, raw, is_private=False):
        path = os.path.join(args.out_dir, name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600 if is_private else 0o644
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        print(f"  wrote {path} ({len(raw)} bytes)")

    write("kem_private.raw", kem_priv.private_bytes_raw(), is_private=True)
    write("kem_public.raw", kem_priv.public_key().public_bytes_raw(), is_private=False)
    write("sig_private.raw", sig_priv.private_bytes_raw(), is_private=True)
    write("sig_public.raw", sig_priv.public_key().public_bytes_raw(), is_private=False)
    print(f"keypairs written to {args.out_dir}/")
    return 0


def cmd_encrypt(args):
    kem_pub = pqc.MLKEM1024PublicKey.from_public_bytes(_read_key_bytes(args.kem_pub))
    sig_priv = pqc.MLDSA87PrivateKey.from_private_bytes(_read_key_bytes(args.sig_priv))

    if args.plaintext is not None:
        pt = args.plaintext.encode()
    else:
        with open(args.infile, "rb") as fh:
            pt = fh.read()

    kdf_mode = "raw" if args.kdf == "auto" else args.kdf
    env = encrypt_envelope(pt, kem_pub, sig_priv, kdf=kdf_mode)
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

    if args.seed:
        kem_priv = pqc.MLKEM1024PrivateKey.from_seed_bytes(_read_key_bytes(args.seed))
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

    common_kdf = dict(choices=["raw", "hkdf", "auto"], default="raw",
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
    kgrp.add_argument("--kem-priv", help="ML-KEM-1024 private key file (64B seed, 3168B raw, or DER)")
    kgrp.add_argument("--seed", help="ML-KEM-1024 keygen seed file (64 bytes)")
    d.add_argument("--kdf", choices=["raw", "hkdf", "auto"], default="auto",
                   help="AES-key derivation (default: auto tries raw then hkdf)")
    d.add_argument("--known-prefix", default="msbj")
    d.add_argument("--no-verify", action="store_true", help="skip signature check")
    d.set_defaults(func=cmd_decrypt)
    return p


def main():
    args = build_parser().parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
