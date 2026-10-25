# crypto-sentinel

A decryption and cryptanalysis toolkit, plus a hybrid Post-Quantum Cryptography (PQC) envelope driver for `pass.txt.pqenc`.

## Layout

```
crypto_engine/
  encoding.py    base64 / base32 / hex / url-safe decoders
  classical.py   Caesar, ROT13, Atbash, Vigenere
  xor.py         single-byte & repeating-key XOR (+ known-plaintext key recovery)
  rsa.py         textbook-RSA weak-parameter attacks (factoring, low-e root)
  aes_ecb.py     AES-ECB decrypt + AES-GCM helper for AEAD envelopes
  hashes.py      hash identification + small-dictionary reversal
  pqc.py         ML-KEM-1024, ML-DSA-87, HKDF-SHA256, and AES-GCM/ECB (OpenSSL 3.5+ / cryptography)
  analyzer.py    solve_with_hint(): fan every module out against a blob
inspect_pqenc.py quick raw-bytes inspector (size, hex dump, format guess)
solve.py         driver for pass.txt.pqenc (supports --kem-priv, --seed, and AES_KEY_HEX)
generate.py      build / open the hybrid PQC envelope (ML-KEM-1024 + AES-256-GCM, ML-DSA-87)
tests/           automated unit and CLI integration test suite
KEYHUNT.md       findings log for the pass.txt.pqenc key hunt
```

## Prerequisites

* Python 3.9+
* OpenSSL 3.5+ (`libcrypto` with `ML-KEM-1024` and `ML-DSA-87`, e.g., Homebrew `openssl@3`) and/or `cryptography>=42.0.0` (`pip install -r requirements.txt`).

## Usage

```bash
# 1. Inspect an unknown file before choosing an attack
python3 inspect_pqenc.py pass.txt.pqenc

# 2. Solve or identify with a known plaintext prefix
python3 solve.py pass.txt.pqenc msbj

# 3. Run the automated test suite
python3 -m unittest discover -s tests -v
```

## Generating / decrypting the PQC envelope

`generate.py` is a reference implementation of the exact envelope scheme. Its `selftest` round-trips a 229-byte message and asserts the generated field byte-lengths match `pass.txt.pqenc` (1568 / 2592 / 4627 / 12 / 16):

```bash
python3 generate.py selftest           # prove format fidelity + round-trip
python3 generate.py keygen --out-dir keys
python3 generate.py encrypt --kem-pub keys/kem_public.raw \
    --sig-priv keys/sig_private.raw --plaintext "msbj..." --out env.json
```

Once the organizers provide the real ML-KEM-1024 private key (64-byte seed, 3168-byte raw decapsulation key, or DER key), decryption is a one-liner via either `generate.py` or `solve.py`:

```bash
python3 generate.py decrypt --envelope pass.txt.pqenc --kem-priv KEYFILE
# or via solve.py (automatically tries both raw and HKDF key derivation):
python3 solve.py pass.txt.pqenc msbj --kem-priv KEYFILE
# or, if a 64-byte seed file:
python3 solve.py pass.txt.pqenc msbj --seed SEEDFILE
```

Generated key files (`keys/`, `*.raw`) are created with `0600` private permissions, gitignored, and never committed.

## What `pass.txt.pqenc` actually is

Inspection shows it is **not** a classical / XOR / RSA / AES-ECB target. It is a JSON envelope for a hybrid post-quantum scheme. The field byte-lengths identify it precisely:

| field        | bytes | meaning                         |
|--------------|-------|---------------------------------|
| `kem_cipher` | 1568  | ML-KEM-1024 (Kyber1024) KEM ct  |
| `public_key` | 2592  | ML-DSA-87 (Dilithium5) pubkey   |
| `signature`  | 4627  | ML-DSA-87 signature             |
| `nonce`      | 12    | AES-GCM nonce                   |
| `auth_tag`   | 16    | AES-GCM auth tag                |
| `ciphertext` | 229   | payload under AES-256-GCM       |

The payload is encrypted with AES-256-GCM, whose key comes from ML-KEM-1024 decapsulation. That key is a full 256-bit secret, so the `msbj` prefix gives no brute-force leverage: **decryption requires the KEM private (decapsulation) key.** Once a 32-byte AES-GCM key or ML-KEM-1024 private key is supplied out of band, the toolkit finishes the decrypt:

```bash
AES_KEY_HEX=<64 hex chars> python3 solve.py
```
