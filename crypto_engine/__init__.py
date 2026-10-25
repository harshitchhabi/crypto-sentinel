"""crypto_engine: a small toolkit of decryption / decoding primitives.

Modules:
    encoding   -- base64 / base32 / hex / url-safe transforms
    classical  -- Caesar, ROT13, Vigenere, Atbash
    xor        -- single-byte and repeating-key XOR (with keyspace search)
    rsa        -- textbook RSA helpers (small-modulus factoring, low-e)
    aes_ecb    -- AES-ECB decrypt + AES-GCM helpers
    hashes     -- hash identification and small-dictionary reversal
    pqc        -- ML-KEM-1024, ML-DSA-87, HKDF, and OpenSSL/cryptography bridge
    analyzer   -- orchestrates the above against an unknown blob
"""

__all__ = [
    "encoding",
    "classical",
    "xor",
    "rsa",
    "aes_ecb",
    "hashes",
    "pqc",
    "analyzer",
]
