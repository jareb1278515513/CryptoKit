"""AES symmetric encryption helpers."""

from __future__ import annotations

from Crypto.Cipher import AES


class SymmetricError(ValueError):
    """Raised when symmetric crypto operations fail."""


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise SymmetricError("invalid padded payload length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise SymmetricError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise SymmetricError("invalid padding")
    return data[:-pad_len]


def _validate_key(key: bytes) -> bytes:
    normalized = bytes(key)
    if len(normalized) not in (16, 24, 32):
        raise SymmetricError("AES key size must be 16, 24 or 32 bytes")
    return normalized


def aes_encrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    payload = bytes(raw)
    secret = _validate_key(key)
    mode_lower = mode.lower()

    if mode_lower == "ecb":
        cipher = AES.new(secret, AES.MODE_ECB)
        return cipher.encrypt(_pkcs7_pad(payload))

    if mode_lower == "cbc":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CBC requires 16-byte iv")
        cipher = AES.new(secret, AES.MODE_CBC, iv=bytes(iv))
        return cipher.encrypt(_pkcs7_pad(payload))

    if mode_lower == "ctr":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CTR requires 16-byte iv")
        cipher = AES.new(secret, AES.MODE_CTR, nonce=b"", initial_value=bytes(iv))
        return cipher.encrypt(payload)

    raise SymmetricError("unsupported AES mode")


def aes_decrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    payload = bytes(raw)
    secret = _validate_key(key)
    mode_lower = mode.lower()

    if mode_lower == "ecb":
        cipher = AES.new(secret, AES.MODE_ECB)
        return _pkcs7_unpad(cipher.decrypt(payload))

    if mode_lower == "cbc":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CBC requires 16-byte iv")
        cipher = AES.new(secret, AES.MODE_CBC, iv=bytes(iv))
        return _pkcs7_unpad(cipher.decrypt(payload))

    if mode_lower == "ctr":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CTR requires 16-byte iv")
        cipher = AES.new(secret, AES.MODE_CTR, nonce=b"", initial_value=bytes(iv))
        return cipher.decrypt(payload)

    raise SymmetricError("unsupported AES mode")
