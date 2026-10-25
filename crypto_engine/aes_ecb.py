"""AES helpers: ECB decryption plus a GCM helper for AEAD envelopes.

ECB is the attackable classical mode; the GCM helper exists so the
analyzer can finish a hybrid envelope once a symmetric key has been
recovered by some other means (e.g. KEM decapsulation).
"""

from . import pqc


def _strip_pkcs7(data, block=16, strict=False):
    if not data:
        return None if strict else data
    pad = data[-1]
    if 1 <= pad <= block and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return None if strict else data


def decrypt_ecb(ciphertext, key, unpad=True, strict_unpad=False):
    """AES-ECB decrypt. ``key`` must be 16/24/32 bytes; ct a block multiple."""
    out = pqc.aes_ecb_decrypt(ciphertext, key)
    if out is None:
        return None
    return _strip_pkcs7(out, strict=strict_unpad) if unpad else out


def decrypt_gcm(ciphertext, key, nonce, tag, aad=None):
    """AES-GCM decrypt. Returns plaintext bytes or None on auth failure."""
    return pqc.aes_gcm_decrypt(ciphertext, key, nonce, tag, aad=aad)
