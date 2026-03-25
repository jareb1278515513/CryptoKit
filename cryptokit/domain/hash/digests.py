"""Hash, HMAC and PBKDF2 primitives."""

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
    """Raised when a hash primitive cannot be executed."""


def _require_algorithm(algorithm: str) -> str:
    lowered = algorithm.lower()
    if lowered not in SUPPORTED_DIGESTS:
        raise HashError(f"unsupported digest algorithm: {algorithm}")
    if lowered == "ripemd160" and "ripemd160" not in hashlib.algorithms_available:
        raise HashError("ripemd160 is not available in current runtime")
    return lowered


def digest(raw: bytes, algorithm: str) -> bytes:
    algo = _require_algorithm(algorithm)
    try:
        return hashlib.new(algo, bytes(raw)).digest()
    except (TypeError, ValueError) as exc:
        raise HashError("invalid digest input") from exc


def digest_hex(raw: bytes, algorithm: str) -> str:
    return digest(raw=raw, algorithm=algorithm).hex()


def hmac_digest(raw: bytes, key: bytes, algorithm: str) -> bytes:
    algo = _require_algorithm(algorithm)
    try:
        return hmac.new(bytes(key), bytes(raw), algo).digest()
    except (TypeError, ValueError) as exc:
        raise HashError("invalid HMAC input") from exc


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
        raise HashError("iterations must be > 0")
    if dklen <= 0:
        raise HashError("dklen must be > 0")
    try:
        return hashlib.pbkdf2_hmac(algo, bytes(password), bytes(salt), iterations, dklen)
    except (TypeError, ValueError) as exc:
        raise HashError("invalid PBKDF2 input") from exc
