#!/usr/bin/env python3
"""Driver: solve pass.txt.pqenc using the crypto_engine toolkit.

Usage:
    python3 solve.py [FILE] [KNOWN_PREFIX] [--kem-priv KEYFILE | --seed SEEDFILE | --aes-key-hex HEX]

Inspection showed FILE is a JSON envelope for a hybrid post-quantum
scheme (ML-KEM-1024 KEM + AES-256-GCM, signed with ML-DSA-87), not a
classical / XOR / RSA / AES-ECB target. The analyzer therefore identifies
the envelope and reports exactly what is needed to finish it.

If you have recovered the ML-KEM-1024 private key / seed or the 32-byte
AES-GCM key, supply it and the payload decrypts immediately:

    python3 solve.py pass.txt.pqenc msbj --kem-priv keys/kem_private.raw
    AES_KEY_HEX=<64 hex chars> python3 solve.py
"""

import argparse
import os
import sys

from crypto_engine import analyzer, pqc


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("filepath", nargs="?", default="pass.txt.pqenc",
                   help="Path to the encrypted file (default: pass.txt.pqenc)")
    p.add_argument("known_prefix", nargs="?", default="msbj",
                   help="Known plaintext prefix (default: msbj)")
    p.add_argument("--kem-priv", help="ML-KEM-1024 private key file (64B seed, 3168B raw, or DER)")
    p.add_argument("--seed", help="ML-KEM-1024 64-byte seed file")
    p.add_argument("--aes-key-hex", help="Hex-encoded 32-byte AES-256-GCM key (or set AES_KEY_HEX)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    filepath = args.filepath
    known_prefix = args.known_prefix

    aes_key = None
    key_hex = args.aes_key_hex or os.environ.get("AES_KEY_HEX")
    if key_hex:
        try:
            aes_key = bytes.fromhex(key_hex.strip())
        except ValueError as exc:
            print(f"error: invalid hex in AES key: {exc}", file=sys.stderr)
            return 1

    kem_private = None
    if args.seed:
        kem_private = pqc.MLKEM1024PrivateKey.from_seed_bytes(pqc.read_key_bytes(args.seed))
    elif args.kem_priv:
        kem_private = pqc.MLKEM1024PrivateKey.from_private_bytes(pqc.read_key_bytes(args.kem_priv))

    result = analyzer.solve_with_hint(
        filepath, known_prefix, aes_key=aes_key, kem_private=kem_private
    )

    print(f"target:       {filepath}")
    print(f"known prefix: {known_prefix!r}")
    print(f"container:    {result['container']}")
    print()

    if result["container"] == "pqc-envelope":
        d = result["details"]
        print("scheme identification (from field byte-lengths):")
        for k, v in d.get("field_sizes", {}).items():
            print(f"  {k:12s} {v} bytes")
        print(f"  => KEM:       {d['kem']}")
        print(f"  => signature: {d['signature']}")
        print(f"  => AEAD:      {d['aead']}")
        print()

    print("methods tried:")
    for a in result["attempts"]:
        print(f"  - {a}")
    print()

    if result["success"]:
        pt = result["plaintext"]
        try:
            shown = pt.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            shown = repr(pt)
        print(f"SUCCESS via {result['method']}")
        print(f"plaintext: {shown}")
        return 0
    else:
        print("NOT SOLVED with available inputs.")
        blocked = result["details"].get("blocked_on")
        if blocked:
            print(f"blocked on: {blocked}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
