"""AES 对称加密工具。"""

from __future__ import annotations

from Crypto.Cipher import AES


class SymmetricError(ValueError):
    """对称加密操作失败时抛出。"""


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """执行 PKCS#7 填充。

    Args:
        data: 原始明文字节串。
        block_size: 分组大小。

    Returns:
        bytes: 填充后的字节串。
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """移除 PKCS#7 填充。

    Args:
        data: 待去填充字节串。
        block_size: 分组大小。

    Returns:
        bytes: 去填充后的字节串。

    Raises:
        SymmetricError: 填充格式不合法时抛出。
    """
    if not data or len(data) % block_size != 0:
        raise SymmetricError("填充数据长度无效")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise SymmetricError("填充格式无效")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise SymmetricError("填充格式无效")
    return data[:-pad_len]


def _validate_key(key: bytes) -> bytes:
    """校验 AES 密钥长度。

    Args:
        key: 输入密钥字节串。

    Returns:
        bytes: 标准化后的密钥。

    Raises:
        SymmetricError: 密钥长度不合法时抛出。
    """
    normalized = bytes(key)
    if len(normalized) not in (16, 24, 32):
        raise SymmetricError("AES 密钥长度必须为 16、24 或 32 字节")
    return normalized


def aes_encrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    """执行 AES 加密。

    Args:
        raw: 明文字节串。
        key: 密钥字节串。
        mode: 模式，支持 `ecb`、`cbc`、`ctr`。
        iv: 初始化向量，`cbc/ctr` 模式必填。

    Returns:
        bytes: 密文字节串。

    Raises:
        SymmetricError: 参数或模式不合法时抛出。
    """
    payload = bytes(raw)
    secret = _validate_key(key)
    mode_lower = mode.lower()

    if mode_lower == "ecb":
        cipher = AES.new(secret, AES.MODE_ECB)
        return cipher.encrypt(_pkcs7_pad(payload))

    if mode_lower == "cbc":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CBC 需要 16 字节 IV")
        cipher = AES.new(secret, AES.MODE_CBC, iv=bytes(iv))
        return cipher.encrypt(_pkcs7_pad(payload))

    if mode_lower == "ctr":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CTR 需要 16 字节 IV")
        cipher = AES.new(secret, AES.MODE_CTR, nonce=b"", initial_value=bytes(iv))
        return cipher.encrypt(payload)

    raise SymmetricError("不支持的 AES 模式")


def aes_decrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    """执行 AES 解密。

    Args:
        raw: 密文字节串。
        key: 密钥字节串。
        mode: 模式，支持 `ecb`、`cbc`、`ctr`。
        iv: 初始化向量，`cbc/ctr` 模式必填。

    Returns:
        bytes: 明文字节串。

    Raises:
        SymmetricError: 参数或模式不合法时抛出。
    """
    payload = bytes(raw)
    secret = _validate_key(key)
    mode_lower = mode.lower()

    if mode_lower == "ecb":
        cipher = AES.new(secret, AES.MODE_ECB)
        return _pkcs7_unpad(cipher.decrypt(payload))

    if mode_lower == "cbc":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CBC 需要 16 字节 IV")
        cipher = AES.new(secret, AES.MODE_CBC, iv=bytes(iv))
        return _pkcs7_unpad(cipher.decrypt(payload))

    if mode_lower == "ctr":
        if iv is None or len(iv) != 16:
            raise SymmetricError("AES-CTR 需要 16 字节 IV")
        cipher = AES.new(secret, AES.MODE_CTR, nonce=b"", initial_value=bytes(iv))
        return cipher.decrypt(payload)

    raise SymmetricError("不支持的 AES 模式")
