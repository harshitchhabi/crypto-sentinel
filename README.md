# crypto-sentinel

A small decryption / crypto-analysis toolkit, plus a driver that solves a
known-prefix challenge file.

## Layout

```
crypto_engine/
  encoding.py    base64 / base32 / hex / url-safe decoders
  classical.py   Caesar, ROT13, Atbash, Vigenere
  xor.py         single-byte & repeating-key XOR (+ known-plaintext key recovery)
  rsa.py         textbook-RSA weak-parameter attacks (factoring, low-e root)
  aes_ecb.py     AES-ECB decrypt + AES-GCM helper for AEAD envelopes
  hashes.py      hash identification + small-dictionary reversal
  analyzer.py    solve_with_hint(): fan every module out against a blob
inspect_pqenc.py quick raw-bytes inspector (size, hex dump, format guess)
solve.py         driver for pass.txt.pqenc
generate.py      build / open the hybrid PQC envelope (ML-KEM-1024 + AES-256-GCM, ML-DSA-87)
KEYHUNT.md       findings log for the pass.txt.pqenc key hunt
```

## Usage

```bash
# 1. Inspect an unknown file before choosing an attack
python3 inspect_pqenc.py pass.txt.pqenc

# 2. Solve with a known plaintext prefix
python3 solve.py pass.txt.pqenc msbj
```

## Generating / decrypting the PQC envelope

`generate.py` is a reference implementation of the exact envelope scheme.
Its `selftest` round-trips a message and asserts the generated field
byte-lengths match `pass.txt.pqenc` (1568 / 2592 / 4627 / 12 / 16):

```bash
python3 generate.py selftest           # prove format fidelity + round-trip
python3 generate.py keygen --out-dir keys
python3 generate.py encrypt --kem-pub keys/kem_public.raw \
    --sig-priv keys/sig_private.raw --plaintext "msbj..." --out env.json
```

Once the organizers provide the real ML-KEM-1024 private key (or its
keygen seed), decryption is a one-liner:

```bash
python3 generate.py decrypt --envelope pass.txt.pqenc --kem-priv KEYFILE
# or, if a seed:  --seed SEEDFILE
# if they used HKDF instead of the raw shared secret:  --kdf hkdf
```

Generated key files (`keys/`, `*.raw`) are gitignored and never committed.

`solve_with_hint(filepath, known_prefix)` loads the file, tries every
applicable module, and reports the first method whose decrypted output
starts with `known_prefix`.

## What `pass.txt.pqenc` actually is

Inspection shows it is **not** a classical / XOR / RSA / AES-ECB target.
It is a JSON envelope for a hybrid post-quantum scheme. The field
byte-lengths identify it precisely:

| field        | bytes | meaning                         |
|--------------|-------|---------------------------------|
| `kem_cipher` | 1568  | ML-KEM-1024 (Kyber1024) KEM ct  |
| `public_key` | 2592  | ML-DSA-87 (Dilithium5) pubkey   |
| `signature`  | 4627  | ML-DSA-87 signature             |
| `nonce`      | 12    | AES-GCM nonce                   |
| `auth_tag`   | 16    | AES-GCM auth tag                |
| `ciphertext` | 229   | payload under AES-256-GCM       |

The payload is encrypted with AES-256-GCM, whose key comes from ML-KEM-1024
decapsulation. That key is a full 256-bit secret, so the `msbj` prefix
gives no brute-force leverage: **decryption requires the KEM private
(decapsulation) key.** The analyzer identifies the scheme and, once a
32-byte AES-GCM key is supplied out of band, finishes the decrypt:

```bash
AES_KEY_HEX=<64 hex chars> python3 solve.py
```
