"""SM4 对称加密工具（带后端回退）。"""

from __future__ import annotations

from .aes import SymmetricError, _pkcs7_pad, _pkcs7_unpad

BLOCK_SIZE = 16


def _validate_key(key: bytes) -> bytes:
    normalized = bytes(key)
    if len(normalized) != BLOCK_SIZE:
        raise SymmetricError("SM4 密钥长度必须为 16 字节")
    return normalized


def _cryptography_sm4(
    raw: bytes,
    *,
    key: bytes,
    mode: str,
    iv: bytes | None,
    encrypt: bool,
) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as exc:
        raise SymmetricError("cryptography 后端不可用") from exc

    mode_lower = mode.lower()
    if mode_lower == "ecb":
        block_mode = modes.ECB()
    elif mode_lower == "cbc":
        if iv is None or len(iv) != BLOCK_SIZE:
            raise SymmetricError("SM4-CBC 需要 16 字节 IV")
        block_mode = modes.CBC(bytes(iv))
    elif mode_lower == "ctr":
        if iv is None or len(iv) != BLOCK_SIZE:
            raise SymmetricError("SM4-CTR 需要 16 字节 IV")
        block_mode = modes.CTR(bytes(iv))
    else:
        raise SymmetricError("不支持的 SM4 模式")

    cipher = Cipher(algorithms.SM4(bytes(key)), block_mode)
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(bytes(raw)) + ctx.finalize()


def sm4_encrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    payload = bytes(raw)
    secret = _validate_key(key)
    mode_lower = mode.lower()

    if mode_lower in ("ecb", "cbc"):
        payload = _pkcs7_pad(payload, BLOCK_SIZE)

    return _cryptography_sm4(payload, key=secret, mode=mode_lower, iv=iv, encrypt=True)


def sm4_decrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    payload = bytes(raw)
    secret = _validate_key(key)
    mode_lower = mode.lower()

    plain = _cryptography_sm4(payload, key=secret, mode=mode_lower, iv=iv, encrypt=False)
    if mode_lower in ("ecb", "cbc"):
        return _pkcs7_unpad(plain, BLOCK_SIZE)
    return plain
