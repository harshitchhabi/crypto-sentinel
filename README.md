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
```

## Usage

```bash
# 1. Inspect an unknown file before choosing an attack
python3 inspect_pqenc.py pass.txt.pqenc

# 2. Solve with a known plaintext prefix
python3 solve.py pass.txt.pqenc msbj
```

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
