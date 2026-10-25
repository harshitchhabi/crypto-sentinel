"""Post-quantum and AEAD primitives backed by PyCA ``cryptography`` or
OpenSSL 3.5+ ``libcrypto`` via ``ctypes``.

Standard PyPI/Homebrew wheels of ``cryptography`` on macOS/Linux link against
OpenSSL, where ``cryptography`` disables its ``mlkem`` and ``mldsa`` bindings
(restricting them to BoringSSL / AWS-LC). Meanwhile, OpenSSL 3.5+ natively
implements FIPS 203 (``ML-KEM-1024``) and FIPS 204 (``ML-DSA-87``) in
``libcrypto``. This module transparently bridges both backends so PQC
keygen, encapsulation, decapsulation, signing, verification, and AES-GCM/ECB
work across standard Python environments.
"""

import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import os

_RAW_KEY_SIZES = frozenset({
    32,    # ML-DSA-87 seed / AES-256 key
    64,    # ML-KEM-1024 seed (d || z)
    1568,  # ML-KEM-1024 public key / ciphertext
    2592,  # ML-DSA-87 public key
    3168,  # ML-KEM-1024 expanded private key
    4896,  # ML-DSA-87 expanded private key
})


class _OSSL_PARAM(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_char_p),
        ("data_type", ctypes.c_uint),
        ("data", ctypes.c_void_p),
        ("data_size", ctypes.c_size_t),
        ("return_size", ctypes.c_size_t),
    ]


_LIBCRYPTO = None


def _load_libcrypto():
    """Load an OpenSSL 3.5+ libcrypto shared library with PQC support."""
    global _LIBCRYPTO
    if _LIBCRYPTO is not None:
        return _LIBCRYPTO

    candidates = [
        os.environ.get("LIBCRYPTO_PATH"),
        "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
        "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
        "/opt/homebrew/lib/libcrypto.dylib",
        "/usr/local/lib/libcrypto.dylib",
        ctypes.util.find_library("crypto"),
    ]
    for path in candidates:
        if not path:
            continue
        try:
            lib = ctypes.CDLL(path)
            if not hasattr(lib, "EVP_PKEY_Q_keygen"):
                continue
            _bind_libcrypto(lib)
            _LIBCRYPTO = lib
            return lib
        except OSError:
            continue
    raise RuntimeError(
        "Could not locate an OpenSSL 3.5+ libcrypto library supporting ML-KEM-1024 / ML-DSA-87."
    )


def _bind_libcrypto(lib):
    lib.EVP_PKEY_Q_keygen.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_PKEY_Q_keygen.restype = ctypes.c_void_p
    lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
    lib.EVP_PKEY_free.restype = None

    lib.EVP_PKEY_get_raw_public_key.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)
    ]
    lib.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int

    lib.EVP_PKEY_get_raw_private_key.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)
    ]
    lib.EVP_PKEY_get_raw_private_key.restype = ctypes.c_int

    lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
    ]
    lib.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p

    lib.EVP_PKEY_new_raw_private_key_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
    ]
    lib.EVP_PKEY_new_raw_private_key_ex.restype = ctypes.c_void_p

    lib.EVP_PKEY_get_octet_string_param.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)
    ]
    lib.EVP_PKEY_get_octet_string_param.restype = ctypes.c_int

    lib.OSSL_PARAM_construct_octet_string.argtypes = [
        ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t
    ]
    lib.OSSL_PARAM_construct_octet_string.restype = _OSSL_PARAM
    lib.OSSL_PARAM_construct_end.argtypes = []
    lib.OSSL_PARAM_construct_end.restype = _OSSL_PARAM

    lib.EVP_PKEY_CTX_new_from_name.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
    ]
    lib.EVP_PKEY_CTX_new_from_name.restype = ctypes.c_void_p
    lib.EVP_PKEY_CTX_new_from_pkey.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p
    ]
    lib.EVP_PKEY_CTX_new_from_pkey.restype = ctypes.c_void_p
    lib.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_PKEY_CTX_free.restype = None

    lib.EVP_PKEY_fromdata_init.argtypes = [ctypes.c_void_p]
    lib.EVP_PKEY_fromdata_init.restype = ctypes.c_int
    lib.EVP_PKEY_fromdata.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int,
        ctypes.POINTER(_OSSL_PARAM)
    ]
    lib.EVP_PKEY_fromdata.restype = ctypes.c_int

    lib.EVP_PKEY_encapsulate_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.EVP_PKEY_encapsulate_init.restype = ctypes.c_int
    lib.EVP_PKEY_encapsulate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)
    ]
    lib.EVP_PKEY_encapsulate.restype = ctypes.c_int

    lib.EVP_PKEY_decapsulate_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.EVP_PKEY_decapsulate_init.restype = ctypes.c_int
    lib.EVP_PKEY_decapsulate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p, ctypes.c_size_t
    ]
    lib.EVP_PKEY_decapsulate.restype = ctypes.c_int

    lib.EVP_MD_CTX_new.argtypes = []
    lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
    lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_MD_CTX_free.restype = None

    lib.EVP_DigestSignInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p
    ]
    lib.EVP_DigestSignInit_ex.restype = ctypes.c_int
    lib.EVP_DigestSign.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p, ctypes.c_size_t
    ]
    lib.EVP_DigestSign.restype = ctypes.c_int

    lib.EVP_DigestVerifyInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p
    ]
    lib.EVP_DigestVerifyInit_ex.restype = ctypes.c_int
    lib.EVP_DigestVerify.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t
    ]
    lib.EVP_DigestVerify.restype = ctypes.c_int

    lib.d2i_AutoPrivateKey.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.c_long,
    ]
    lib.d2i_AutoPrivateKey.restype = ctypes.c_void_p

    lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
    lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]
    lib.EVP_CIPHER_free.restype = None
    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_CIPHER_CTX_free.restype = None
    lib.EVP_CipherInit_ex2.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_void_p
    ]
    lib.EVP_CipherInit_ex2.restype = ctypes.c_int
    lib.EVP_CipherUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int
    ]
    lib.EVP_CipherUpdate.restype = ctypes.c_int
    lib.EVP_CipherFinal_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)
    ]
    lib.EVP_CipherFinal_ex.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p
    ]
    lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int


def _get_raw_public_bytes(lib, pkey):
    length = ctypes.c_size_t(0)
    if lib.EVP_PKEY_get_raw_public_key(pkey, None, ctypes.byref(length)) != 1:
        raise ValueError("Failed to query raw public key length")
    buf = ctypes.create_string_buffer(length.value)
    if lib.EVP_PKEY_get_raw_public_key(pkey, buf, ctypes.byref(length)) != 1:
        raise ValueError("Failed to extract raw public key bytes")
    return buf.raw[:length.value]


def _get_raw_private_bytes(lib, pkey):
    length = ctypes.c_size_t(0)
    if lib.EVP_PKEY_get_raw_private_key(pkey, None, ctypes.byref(length)) != 1:
        raise ValueError("Failed to query raw private key length")
    buf = ctypes.create_string_buffer(length.value)
    if lib.EVP_PKEY_get_raw_private_key(pkey, buf, ctypes.byref(length)) != 1:
        raise ValueError("Failed to extract raw private key bytes")
    return buf.raw[:length.value]


def _get_seed_bytes(lib, pkey, max_len=64):
    buf = ctypes.create_string_buffer(max_len)
    out_len = ctypes.c_size_t(0)
    rc = lib.EVP_PKEY_get_octet_string_param(
        pkey, b"seed", buf, max_len, ctypes.byref(out_len)
    )
    if rc == 1 and out_len.value > 0:
        return buf.raw[:out_len.value]
    return None


def _pkey_from_seed(lib, alg_bytes, seed_bytes):
    seed_buf = ctypes.create_string_buffer(seed_bytes, len(seed_bytes))
    params = (_OSSL_PARAM * 2)()
    params[0] = lib.OSSL_PARAM_construct_octet_string(
        b"seed", ctypes.cast(seed_buf, ctypes.c_void_p), len(seed_bytes)
    )
    params[1] = lib.OSSL_PARAM_construct_end()
    ctx = lib.EVP_PKEY_CTX_new_from_name(None, alg_bytes, None)
    if not ctx:
        raise ValueError(f"Failed to create context for {alg_bytes!r}")
    try:
        if lib.EVP_PKEY_fromdata_init(ctx) != 1:
            raise ValueError("EVP_PKEY_fromdata_init failed")
        pkey = ctypes.c_void_p()
        # 0x87 == EVP_PKEY_KEYPAIR
        if lib.EVP_PKEY_fromdata(ctx, ctypes.byref(pkey), 0x87, params) != 1 or not pkey.value:
            raise ValueError(f"Invalid seed bytes for {alg_bytes.decode()}")
        return pkey.value
    finally:
        lib.EVP_PKEY_CTX_free(ctx)


def _pkey_from_der(lib, der_bytes):
    arr = (ctypes.c_ubyte * len(der_bytes)).from_buffer_copy(der_bytes)
    ptr = ctypes.cast(arr, ctypes.POINTER(ctypes.c_ubyte))
    pkey = lib.d2i_AutoPrivateKey(None, ctypes.byref(ptr), len(der_bytes))
    if not pkey:
        raise ValueError("Unable to parse private key as seed, raw key, or DER PKCS#8")
    return pkey


class MLKEM1024PublicKey:
    """ML-KEM-1024 public (encapsulation) key."""

    def __init__(self, pkey_ptr, lib=None):
        self._lib = lib or _load_libcrypto()
        self._pkey = pkey_ptr

    def __del__(self):
        if getattr(self, "_pkey", None) and getattr(self, "_lib", None):
            self._lib.EVP_PKEY_free(self._pkey)
            self._pkey = None

    @classmethod
    def from_public_bytes(cls, data):
        if not isinstance(data, (bytes, bytearray)) or len(data) != 1568:
            raise ValueError(f"ML-KEM-1024 public key must be 1568 bytes (got {len(data) if isinstance(data, (bytes, bytearray)) else type(data)})")
        lib = _load_libcrypto()
        raw = bytes(data)
        pkey = lib.EVP_PKEY_new_raw_public_key_ex(None, b"ML-KEM-1024", None, raw, len(raw))
        if not pkey:
            raise ValueError("Invalid ML-KEM-1024 public key bytes")
        return cls(pkey, lib)

    def encapsulate(self):
        """Return ``(shared_secret, ciphertext)`` (32 bytes, 1568 bytes)."""
        ctx = self._lib.EVP_PKEY_CTX_new_from_pkey(None, self._pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new_from_pkey failed")
        try:
            if self._lib.EVP_PKEY_encapsulate_init(ctx, None) != 1:
                raise RuntimeError("EVP_PKEY_encapsulate_init failed")
            ct_len = ctypes.c_size_t(0)
            ss_len = ctypes.c_size_t(0)
            if self._lib.EVP_PKEY_encapsulate(
                ctx, None, ctypes.byref(ct_len), None, ctypes.byref(ss_len)
            ) != 1:
                raise RuntimeError("EVP_PKEY_encapsulate size query failed")
            ct_buf = ctypes.create_string_buffer(ct_len.value)
            ss_buf = ctypes.create_string_buffer(ss_len.value)
            if self._lib.EVP_PKEY_encapsulate(
                ctx, ct_buf, ctypes.byref(ct_len), ss_buf, ctypes.byref(ss_len)
            ) != 1:
                raise RuntimeError("EVP_PKEY_encapsulate failed")
            return ss_buf.raw[:ss_len.value], ct_buf.raw[:ct_len.value]
        finally:
            self._lib.EVP_PKEY_CTX_free(ctx)

    def public_bytes_raw(self):
        return _get_raw_public_bytes(self._lib, self._pkey)


class MLKEM1024PrivateKey:
    """ML-KEM-1024 private (decapsulation) key."""

    def __init__(self, pkey_ptr, lib=None):
        self._lib = lib or _load_libcrypto()
        self._pkey = pkey_ptr

    def __del__(self):
        if getattr(self, "_pkey", None) and getattr(self, "_lib", None):
            self._lib.EVP_PKEY_free(self._pkey)
            self._pkey = None

    @classmethod
    def generate(cls):
        lib = _load_libcrypto()
        pkey = lib.EVP_PKEY_Q_keygen(None, None, b"ML-KEM-1024")
        if not pkey:
            raise RuntimeError("Failed to generate ML-KEM-1024 keypair")
        return cls(pkey, lib)

    @classmethod
    def from_seed_bytes(cls, data):
        raw = bytes(data)
        if len(raw) != 64:
            raise ValueError(f"ML-KEM-1024 seed must be 64 bytes (got {len(raw)})")
        lib = _load_libcrypto()
        return cls(_pkey_from_seed(lib, b"ML-KEM-1024", raw), lib)

    @classmethod
    def from_private_bytes(cls, data):
        """Load from 64-byte seed, 3168-byte raw expanded key, or DER PKCS#8."""
        raw = bytes(data)
        lib = _load_libcrypto()
        if len(raw) == 64:
            return cls.from_seed_bytes(raw)
        if len(raw) == 3168:
            pkey = lib.EVP_PKEY_new_raw_private_key_ex(
                None, b"ML-KEM-1024", None, raw, len(raw)
            )
            if not pkey:
                raise ValueError("Invalid 3168-byte ML-KEM-1024 private key")
            return cls(pkey, lib)
        return cls(_pkey_from_der(lib, raw), lib)

    def decapsulate(self, ciphertext):
        raw_ct = bytes(ciphertext)
        if len(raw_ct) != 1568:
            raise ValueError(f"ML-KEM-1024 ciphertext must be 1568 bytes (got {len(raw_ct)})")
        ctx = self._lib.EVP_PKEY_CTX_new_from_pkey(None, self._pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new_from_pkey failed")
        try:
            if self._lib.EVP_PKEY_decapsulate_init(ctx, None) != 1:
                raise RuntimeError("EVP_PKEY_decapsulate_init failed")
            ss_len = ctypes.c_size_t(32)
            ss_buf = ctypes.create_string_buffer(32)
            if self._lib.EVP_PKEY_decapsulate(
                ctx, ss_buf, ctypes.byref(ss_len), raw_ct, len(raw_ct)
            ) != 1:
                raise ValueError("ML-KEM-1024 decapsulation failed")
            return ss_buf.raw[:ss_len.value]
        finally:
            self._lib.EVP_PKEY_CTX_free(ctx)

    def public_key(self):
        pub_raw = _get_raw_public_bytes(self._lib, self._pkey)
        return MLKEM1024PublicKey.from_public_bytes(pub_raw)

    def private_bytes_raw(self):
        """Return 64-byte seed if available, else 3168-byte expanded key."""
        seed = _get_seed_bytes(self._lib, self._pkey, 64)
        if seed is not None and len(seed) == 64:
            return seed
        return _get_raw_private_bytes(self._lib, self._pkey)

    def expanded_private_bytes_raw(self):
        """Return the full 3168-byte expanded decapsulation key."""
        return _get_raw_private_bytes(self._lib, self._pkey)


class MLDSA87PublicKey:
    """ML-DSA-87 public (verification) key."""

    def __init__(self, pkey_ptr, lib=None):
        self._lib = lib or _load_libcrypto()
        self._pkey = pkey_ptr

    def __del__(self):
        if getattr(self, "_pkey", None) and getattr(self, "_lib", None):
            self._lib.EVP_PKEY_free(self._pkey)
            self._pkey = None

    @classmethod
    def from_public_bytes(cls, data):
        raw = bytes(data)
        if len(raw) != 2592:
            raise ValueError(f"ML-DSA-87 public key must be 2592 bytes (got {len(raw)})")
        lib = _load_libcrypto()
        pkey = lib.EVP_PKEY_new_raw_public_key_ex(None, b"ML-DSA-87", None, raw, len(raw))
        if not pkey:
            raise ValueError("Invalid ML-DSA-87 public key bytes")
        return cls(pkey, lib)

    def verify(self, signature, data):
        raw_sig = bytes(signature)
        raw_msg = bytes(data)
        ctx = self._lib.EVP_MD_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if self._lib.EVP_DigestVerifyInit_ex(
                ctx, None, None, None, None, self._pkey, None
            ) != 1:
                raise ValueError("EVP_DigestVerifyInit_ex failed")
            rc = self._lib.EVP_DigestVerify(
                ctx, raw_sig, len(raw_sig), raw_msg, len(raw_msg)
            )
            if rc != 1:
                raise ValueError("ML-DSA-87 signature verification failed")
        finally:
            self._lib.EVP_MD_CTX_free(ctx)

    def public_bytes_raw(self):
        return _get_raw_public_bytes(self._lib, self._pkey)


class MLDSA87PrivateKey:
    """ML-DSA-87 private (signing) key."""

    def __init__(self, pkey_ptr, lib=None):
        self._lib = lib or _load_libcrypto()
        self._pkey = pkey_ptr

    def __del__(self):
        if getattr(self, "_pkey", None) and getattr(self, "_lib", None):
            self._lib.EVP_PKEY_free(self._pkey)
            self._pkey = None

    @classmethod
    def generate(cls):
        lib = _load_libcrypto()
        pkey = lib.EVP_PKEY_Q_keygen(None, None, b"ML-DSA-87")
        if not pkey:
            raise RuntimeError("Failed to generate ML-DSA-87 keypair")
        return cls(pkey, lib)

    @classmethod
    def from_seed_bytes(cls, data):
        raw = bytes(data)
        if len(raw) != 32:
            raise ValueError(f"ML-DSA-87 seed must be 32 bytes (got {len(raw)})")
        lib = _load_libcrypto()
        return cls(_pkey_from_seed(lib, b"ML-DSA-87", raw), lib)

    @classmethod
    def from_private_bytes(cls, data):
        """Load from 32-byte seed, 4896-byte raw expanded key, or DER PKCS#8."""
        raw = bytes(data)
        lib = _load_libcrypto()
        if len(raw) == 32:
            return cls.from_seed_bytes(raw)
        if len(raw) == 4896:
            pkey = lib.EVP_PKEY_new_raw_private_key_ex(
                None, b"ML-DSA-87", None, raw, len(raw)
            )
            if not pkey:
                raise ValueError("Invalid 4896-byte ML-DSA-87 private key")
            return cls(pkey, lib)
        return cls(_pkey_from_der(lib, raw), lib)

    def sign(self, data):
        raw_msg = bytes(data)
        ctx = self._lib.EVP_MD_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if self._lib.EVP_DigestSignInit_ex(
                ctx, None, None, None, None, self._pkey, None
            ) != 1:
                raise RuntimeError("EVP_DigestSignInit_ex failed")
            sig_len = ctypes.c_size_t(0)
            if self._lib.EVP_DigestSign(
                ctx, None, ctypes.byref(sig_len), raw_msg, len(raw_msg)
            ) != 1:
                raise RuntimeError("EVP_DigestSign size query failed")
            sig_buf = ctypes.create_string_buffer(sig_len.value)
            if self._lib.EVP_DigestSign(
                ctx, sig_buf, ctypes.byref(sig_len), raw_msg, len(raw_msg)
            ) != 1:
                raise RuntimeError("EVP_DigestSign failed")
            return sig_buf.raw[:sig_len.value]
        finally:
            self._lib.EVP_MD_CTX_free(ctx)

    def public_key(self):
        pub_raw = _get_raw_public_bytes(self._lib, self._pkey)
        return MLDSA87PublicKey.from_public_bytes(pub_raw)

    def private_bytes_raw(self):
        """Return 32-byte seed if available, else 4896-byte expanded key."""
        seed = _get_seed_bytes(self._lib, self._pkey, 32)
        if seed is not None and len(seed) == 32:
            return seed
        return _get_raw_private_bytes(self._lib, self._pkey)


def hkdf_sha256(key_material, length=32, salt=None, info=b""):
    """RFC 5869 HKDF-SHA256 using Python's standard library ``hmac``."""
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, bytes(key_material), hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + bytes(info) + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


def aes_gcm_encrypt(key, nonce, plaintext, aad=None):
    """Encrypt ``plaintext`` with AES-GCM and return ``(ciphertext, tag)``."""
    key = bytes(key)
    nonce = bytes(nonce)
    plaintext = bytes(plaintext)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
        return ct_and_tag[:-16], ct_and_tag[-16:]
    except ImportError:
        pass

    lib = _load_libcrypto()
    cipher_name = f"AES-{len(key) * 8}-GCM".encode("ascii")
    cipher = lib.EVP_CIPHER_fetch(None, cipher_name, None)
    if not cipher:
        raise ValueError(f"Unsupported AES key size: {len(key)}")
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        if lib.EVP_CipherInit_ex2(ctx, cipher, None, None, 1, None) != 1:
            raise ValueError("EVP_CipherInit_ex2 failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None) != 1:
            raise ValueError("Failed to set GCM nonce length")
        if lib.EVP_CipherInit_ex2(ctx, None, key, nonce, 1, None) != 1:
            raise ValueError("Failed to set GCM key/nonce")
        out_len = ctypes.c_int(0)
        if aad:
            aad_b = bytes(aad)
            if lib.EVP_CipherUpdate(ctx, None, ctypes.byref(out_len), aad_b, len(aad_b)) != 1:
                raise ValueError("Failed to authenticate AAD")
        out_buf = ctypes.create_string_buffer(len(plaintext) + 16)
        if lib.EVP_CipherUpdate(ctx, out_buf, ctypes.byref(out_len), plaintext, len(plaintext)) != 1:
            raise ValueError("EVP_CipherUpdate failed")
        ct = out_buf.raw[:out_len.value]
        fin_len = ctypes.c_int(0)
        if lib.EVP_CipherFinal_ex(ctx, out_buf, ctypes.byref(fin_len)) != 1:
            raise ValueError("EVP_CipherFinal_ex failed")
        tag_buf = ctypes.create_string_buffer(16)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag_buf) != 1:
            raise ValueError("Failed to retrieve GCM tag")
        return ct, tag_buf.raw
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)


def aes_gcm_decrypt(ciphertext, key, nonce, tag, aad=None):
    """Decrypt AES-GCM ``ciphertext`` and return plaintext bytes or ``None``."""
    try:
        key = bytes(key)
        nonce = bytes(nonce)
        ciphertext = bytes(ciphertext)
        tag = bytes(tag)
    except Exception:
        return None
    if len(key) not in (16, 24, 32) or len(tag) != 16 or not nonce:
        return None

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.exceptions import InvalidTag
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        dec = cipher.decryptor()
        if aad:
            dec.authenticate_additional_data(aad)
        try:
            return dec.update(ciphertext) + dec.finalize()
        except InvalidTag:
            return None
    except ImportError:
        pass

    lib = _load_libcrypto()
    cipher_name = f"AES-{len(key) * 8}-GCM".encode("ascii")
    cipher = lib.EVP_CIPHER_fetch(None, cipher_name, None)
    if not cipher:
        return None
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        if lib.EVP_CipherInit_ex2(ctx, cipher, None, None, 0, None) != 1:
            return None
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None) != 1:
            return None
        if lib.EVP_CipherInit_ex2(ctx, None, key, nonce, 0, None) != 1:
            return None
        out_len = ctypes.c_int(0)
        if aad:
            aad_b = bytes(aad)
            if lib.EVP_CipherUpdate(ctx, None, ctypes.byref(out_len), aad_b, len(aad_b)) != 1:
                return None
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        if lib.EVP_CipherUpdate(ctx, out_buf, ctypes.byref(out_len), ciphertext, len(ciphertext)) != 1:
            return None
        pt = out_buf.raw[:out_len.value]
        tag_buf = ctypes.create_string_buffer(tag, len(tag))
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, len(tag), tag_buf) != 1:
            return None
        fin_len = ctypes.c_int(0)
        if lib.EVP_CipherFinal_ex(ctx, out_buf, ctypes.byref(fin_len)) != 1:
            return None
        return pt
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)


def aes_ecb_decrypt(ciphertext, key):
    """Raw AES-ECB block decryption without unpadding."""
    key = bytes(key)
    ciphertext = bytes(ciphertext)
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0 or len(key) not in (16, 24, 32):
        return None

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()
    except ImportError:
        pass

    lib = _load_libcrypto()
    cipher_name = f"AES-{len(key) * 8}-ECB".encode("ascii")
    cipher = lib.EVP_CIPHER_fetch(None, cipher_name, None)
    if not cipher:
        return None
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        if lib.EVP_CipherInit_ex2(ctx, cipher, key, None, 0, None) != 1:
            return None
        lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        out_len = ctypes.c_int(0)
        if lib.EVP_CipherUpdate(ctx, out_buf, ctypes.byref(out_len), ciphertext, len(ciphertext)) != 1:
            return None
        pt = out_buf.raw[:out_len.value]
        fin_len = ctypes.c_int(0)
        if lib.EVP_CipherFinal_ex(ctx, out_buf, ctypes.byref(fin_len)) != 1:
            return None
        return pt + out_buf.raw[:fin_len.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)


def read_key_bytes(path):
    """Read a key file safely as raw bytes, or decode hex/base64 text wrappers.

    Crucially, if the file's raw byte length already matches a known binary
    key/seed length (32, 64, 1568, 2592, 3168, 4896) and is not pure hex text,
    it is returned verbatim without stripping leading/trailing bytes that
    happen to match ASCII whitespace (0x09..0x0d, 0x20).
    """
    with open(path, "rb") as fh:
        data = fh.read()

    stripped = data.strip()
    # 1. Check hex text first (e.g. 64 hex chars = 32 bytes, 128 hex chars = 64 bytes)
    try:
        ascii_str = stripped.decode("ascii")
        if len(ascii_str) >= 2 and len(ascii_str) % 2 == 0 and all(
            c in "0123456789abcdefABCDEF" for c in ascii_str
        ):
            decoded_hex = bytes.fromhex(ascii_str)
            if len(decoded_hex) in _RAW_KEY_SIZES or len(data) not in _RAW_KEY_SIZES:
                return decoded_hex
    except UnicodeDecodeError:
        pass

    # 2. If exact raw key length on disk, preserve raw binary verbatim!
    if len(data) in _RAW_KEY_SIZES:
        return data

    # 3. Try Base64 decoding if the decoded length matches a known key/seed size
    #    or the file is clearly printable text.
    try:
        decoded_b64 = base64.b64decode(stripped, validate=True)
        if decoded_b64 and (
            len(decoded_b64) in _RAW_KEY_SIZES
            or all(32 <= b < 127 or b in (9, 10, 13) for b in data)
        ):
            return decoded_b64
    except Exception:
        pass

    return data
