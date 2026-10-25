"""AES helpers: ECB decryption plus a GCM helper for AEAD envelopes.

ECB is the attackable classical mode; the GCM helper exists so the
analyzer can finish a hybrid envelope once a symmetric key has been
recovered by some other means (e.g. KEM decapsulation).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag


def _strip_pkcs7(data, block=16):
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= block and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def decrypt_ecb(ciphertext, key, unpad=True):
    """AES-ECB decrypt. ``key`` must be 16/24/32 bytes; ct a block multiple."""
    if len(ciphertext) % 16 != 0:
        return None
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    out = dec.update(ciphertext) + dec.finalize()
    return _strip_pkcs7(out) if unpad else out


def decrypt_gcm(ciphertext, key, nonce, tag, aad=None):
    """AES-GCM decrypt. Returns plaintext bytes or None on auth failure."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    if aad:
        dec.authenticate_additional_data(aad)
    try:
        return dec.update(ciphertext) + dec.finalize()
    except InvalidTag:
        return None
