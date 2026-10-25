#!/usr/bin/env python3
"""Driver: solve pass.txt.pqenc using the crypto_engine toolkit.

Usage:
    python3 solve.py [FILE] [KNOWN_PREFIX]

Inspection showed FILE is a JSON envelope for a hybrid post-quantum
scheme (ML-KEM-1024 KEM + AES-256-GCM, signed with ML-DSA-87), not a
classical / XOR / RSA / AES-ECB target. The analyzer therefore identifies
the envelope and reports exactly what is needed to finish it.

If you have recovered the 32-byte AES-GCM key (via KEM decapsulation with
the private key), supply it and the payload decrypts immediately:

    AES_KEY_HEX=<64 hex chars> python3 solve.py
"""

import os
import sys

from crypto_engine import analyzer


def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else "pass.txt.pqenc"
    known_prefix = sys.argv[2] if len(sys.argv) > 2 else "msbj"

    aes_key = None
    key_hex = os.environ.get("AES_KEY_HEX")
    if key_hex:
        aes_key = bytes.fromhex(key_hex)

    result = analyzer.solve_with_hint(filepath, known_prefix, aes_key=aes_key)

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
    else:
        print("NOT SOLVED with available inputs.")
        blocked = result["details"].get("blocked_on")
        if blocked:
            print(f"blocked on: {blocked}")


if __name__ == "__main__":
    main()
