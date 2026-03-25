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
    lowered = algorithm.lower()
    if lowered not in SUPPORTED_DIGESTS:
        raise HashError(f"不支持的摘要算法: {algorithm}")
    return lowered


def _ripemd160_digest(raw: bytes) -> bytes:
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
    algo = _require_algorithm(algorithm)
    try:
        if algo == "ripemd160":
            return _ripemd160_digest(raw)
        return hashlib.new(algo, bytes(raw)).digest()
    except (TypeError, ValueError) as exc:
        raise HashError("摘要输入无效") from exc


def digest_hex(raw: bytes, algorithm: str) -> str:
    return digest(raw=raw, algorithm=algorithm).hex()


def hmac_digest(raw: bytes, key: bytes, algorithm: str) -> bytes:
    algo = _require_algorithm(algorithm)
    try:
        return hmac.new(bytes(key), bytes(raw), algo).digest()
    except (TypeError, ValueError) as exc:
        raise HashError("HMAC 输入无效") from exc


def hmac_digest_hex(raw: bytes, key: bytes, algorithm: str) -> str:
    return hmac_digest(raw=raw, key=key, algorithm=algorithm).hex()


def pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int = 100000,
    dklen: int = 32,
    algorithm: str = "sha256",
) -> bytes:
    algo = _require_algorithm(algorithm)
    if iterations <= 0:
        raise HashError("迭代次数必须大于 0")
    if dklen <= 0:
        raise HashError("派生密钥长度必须大于 0")
    try:
        return hashlib.pbkdf2_hmac(algo, bytes(password), bytes(salt), iterations, dklen)
    except (TypeError, ValueError) as exc:
        raise HashError("PBKDF2 输入无效") from exc
