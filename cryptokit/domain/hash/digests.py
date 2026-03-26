"""哈希、HMAC 与 PBKDF2 原语。"""

from __future__ import annotations

import hashlib
import hmac

SUPPORTED_DIGESTS = {
    "sha1",
    "sha256",
    "sha3_256",
    "sha3_512",
    "ripemd160",
}


class HashError(ValueError):
    """哈希相关操作失败时抛出。"""


def _require_algorithm(algorithm: str) -> str:
    """校验并标准化摘要算法名称。

    Args:
        algorithm: 用户输入算法名。

    Returns:
        str: 标准化后的算法名（小写）。

    Raises:
        HashError: 算法不受支持时抛出。
    """
    lowered = algorithm.lower()
    if lowered not in SUPPORTED_DIGESTS:
        raise HashError(f"不支持的摘要算法: {algorithm}")
    return lowered


def _ripemd160_digest(raw: bytes) -> bytes:
    """计算 RIPEMD160 摘要，支持后端回退。

    Args:
        raw: 待摘要数据。

    Returns:
        bytes: 摘要值。

    Raises:
        HashError: 本地后端均不可用时抛出。
    """
    payload = bytes(raw)

    if "ripemd160" in hashlib.algorithms_available:
        return hashlib.new("ripemd160", payload).digest()

    try:
        from Crypto.Hash import RIPEMD160  # type: ignore[import-not-found]
    except Exception as exc:
        raise HashError(
            "RIPEMD160 不可用：hashlib 与 pycryptodome 后端均不可用"
        ) from exc

    return RIPEMD160.new(payload).digest()


def digest(raw: bytes, algorithm: str) -> bytes:
    """计算指定算法的消息摘要。

    Args:
        raw: 待摘要数据。
        algorithm: 摘要算法名称。

    Returns:
        bytes: 摘要结果。

    Raises:
        HashError: 输入无效或算法计算失败时抛出。
    """
    algo = _require_algorithm(algorithm)
    try:
        if algo == "ripemd160":
            return _ripemd160_digest(raw)
        return hashlib.new(algo, bytes(raw)).digest()
    except (TypeError, ValueError) as exc:
        raise HashError("摘要输入无效") from exc


def digest_hex(raw: bytes, algorithm: str) -> str:
    """计算消息摘要并返回十六进制文本。

    Args:
        raw: 待摘要数据。
        algorithm: 摘要算法名称。

    Returns:
        str: 十六进制摘要文本。
    """
    return digest(raw=raw, algorithm=algorithm).hex()


def hmac_digest(raw: bytes, key: bytes, algorithm: str) -> bytes:
    """计算 HMAC 摘要。

    Args:
        raw: 待认证消息。
        key: HMAC 密钥。
        algorithm: 哈希算法名称。

    Returns:
        bytes: HMAC 结果。

    Raises:
        HashError: 输入无效或计算失败时抛出。
    """
    algo = _require_algorithm(algorithm)
    try:
        return hmac.new(bytes(key), bytes(raw), algo).digest()
    except (TypeError, ValueError) as exc:
        raise HashError("HMAC 输入无效") from exc


def hmac_digest_hex(raw: bytes, key: bytes, algorithm: str) -> str:
    """计算 HMAC 并返回十六进制文本。

    Args:
        raw: 待认证消息。
        key: HMAC 密钥。
        algorithm: 哈希算法名称。

    Returns:
        str: 十六进制 HMAC 文本。
    """
    return hmac_digest(raw=raw, key=key, algorithm=algorithm).hex()


def pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int = 100000,
    dklen: int = 32,
    algorithm: str = "sha256",
) -> bytes:
    """执行 PBKDF2 密钥派生。

    Args:
        password: 口令字节串。
        salt: 盐值字节串。
        iterations: 迭代次数。
        dklen: 输出密钥长度（字节）。
        algorithm: PRF 哈希算法名称。

    Returns:
        bytes: 派生密钥。

    Raises:
        HashError: 参数非法或后端计算失败时抛出。
    """
    algo = _require_algorithm(algorithm)
    if iterations <= 0:
        raise HashError("迭代次数必须大于 0")
    if dklen <= 0:
        raise HashError("派生密钥长度必须大于 0")
    try:
        return hashlib.pbkdf2_hmac(algo, bytes(password), bytes(salt), iterations, dklen)
    except (TypeError, ValueError) as exc:
        raise HashError("PBKDF2 输入无效") from exc
