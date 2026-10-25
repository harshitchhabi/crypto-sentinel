# Key-hunt findings — `pass.txt.pqenc`

Goal: recover the ML-KEM-1024 private (decapsulation) key, or a keygen seed,
needed to decrypt `pass.txt.pqenc`. The known plaintext prefix is `msbj`.

## Target structure (confirmed)

`pass.txt.pqenc` is a JSON envelope for a hybrid post-quantum scheme.
Field byte-lengths identify it exactly:

| field        | bytes | meaning                              |
|--------------|-------|--------------------------------------|
| `kem_cipher` | 1568  | ML-KEM-1024 (Kyber1024) KEM ct       |
| `public_key` | 2592  | ML-DSA-87 (Dilithium5) public key    |
| `signature`  | 4627  | ML-DSA-87 signature                  |
| `nonce`      | 12    | AES-GCM nonce                        |
| `auth_tag`   | 16    | AES-GCM auth tag                     |
| `ciphertext` | 229   | payload (the password) under AES-256-GCM |

The AES-256-GCM key is derived from ML-KEM-1024 decapsulation, so it is a
full 256-bit secret. The `msbj` prefix gives no brute-force leverage.

## Places searched — all ruled out

1. **Git history** (full, un-shallowed; 7 commits, one branch, no tags):
   no added-then-deleted files, no dangling objects, no stash, no
   key/seed strings in any commit or blob. README change was cosmetic.
2. **Image metadata** (exiftool, all fields): PNG has no text chunks/EXIF;
   all four WhatsApp JPEGs are metadata-stripped. Nothing hidden.
3. **Repo structure**: no subdirectories, no dotfiles, no
   `.key`/`.seed`/`.json`/config files out of place.
4. **Binary `strings`** (ASCII + UTF-16LE, read-only, not executed) on
   `ppqqcc.exe` and `zeusfinal.exe`: no keys, hex/base64 blobs, Fernet or
   Kyber references, or packer markers. Any secrets are in packed sections
   plain `strings` cannot reach.

## QR payload — investigated, DEAD END

`sentinel_qr_0007.png` decodes to:

```
https://96269.in/?cipher=gAAAAABqsml7...Zc-2Hd
```

The `cipher=` value is a valid Fernet token (version 0x80, 2026-09-22
timestamp, 16-byte IV, 48-byte AES-CBC ciphertext = 32-byte plaintext,
HMAC). It looked like it might wrap a 32-byte key/seed.

**Resolved (confirmed by organizers' live service):** `96269.in` is the
organizers' own "Sentinel Verify" zero-trust QR-auth demo (Team
SCIFIIINC). It decrypts the Fernet token server-side and displays
`Verified Payload: Sample Pharmaceutical Drug Record-0001` — a sample/demo
payload, **not** the ML-KEM key or the Fernet key. This endpoint is not
where the key is hidden. **Do not pursue further.**

## Status

The ML-KEM private key / seed is not present in any artifact shipped with
the challenge. It must come from the organizers (or from reversing the
binaries, which is out of scope for the read-only pass). `generate.py` is
built as scaffolding so that the moment a real private key/seed is
supplied, decryption is a one-liner.
