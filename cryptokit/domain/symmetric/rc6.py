"""纯 Python RC6-32/20/16 实现。"""

from __future__ import annotations

import struct

from .aes import SymmetricError, _pkcs7_pad, _pkcs7_unpad

W = 32
R = 20
LGW = 5
PW = 0xB7E15163
QW = 0x9E3779B9
MOD = 1 << W
MASK = MOD - 1
BLOCK_BYTES = 16


def _rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (W - n))) & MASK


def _rotr(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | (x << (W - n))) & MASK


def _expand_key(key: bytes) -> list[int]:
    secret = bytes(key)
    if len(secret) == 0:
        raise SymmetricError("RC6 密钥不能为空")

    c = max(1, (len(secret) + 3) // 4)
    l = [0] * c
    for i in range(len(secret) - 1, -1, -1):
        l[i // 4] = ((l[i // 4] << 8) + secret[i]) & MASK

    t = 2 * R + 4
    s = [0] * t
    s[0] = PW
    for i in range(1, t):
        s[i] = (s[i - 1] + QW) & MASK

    a = b = i = j = 0
    for _ in range(3 * max(c, t)):
        a = s[i] = _rotl((s[i] + a + b) & MASK, 3)
        b = l[j] = _rotl((l[j] + a + b) & MASK, (a + b) & 31)
        i = (i + 1) % t
        j = (j + 1) % c

    return s


def _encrypt_block(block: bytes, s: list[int]) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    b = (b + s[0]) & MASK
    d = (d + s[1]) & MASK

    for i in range(1, R + 1):
        t = _rotl((b * ((2 * b + 1) & MASK)) & MASK, LGW)
        u = _rotl((d * ((2 * d + 1) & MASK)) & MASK, LGW)
        a = (_rotl(a ^ t, u) + s[2 * i]) & MASK
        c = (_rotl(c ^ u, t) + s[2 * i + 1]) & MASK
        a, b, c, d = b, c, d, a

    a = (a + s[2 * R + 2]) & MASK
    c = (c + s[2 * R + 3]) & MASK
    return struct.pack("<4I", a, b, c, d)


def _decrypt_block(block: bytes, s: list[int]) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    c = (c - s[2 * R + 3]) & MASK
    a = (a - s[2 * R + 2]) & MASK

    for i in range(R, 0, -1):
        a, b, c, d = d, a, b, c
        u = _rotl((d * ((2 * d + 1) & MASK)) & MASK, LGW)
        t = _rotl((b * ((2 * b + 1) & MASK)) & MASK, LGW)
        c = _rotr((c - s[2 * i + 1]) & MASK, t) ^ u
        a = _rotr((a - s[2 * i]) & MASK, u) ^ t

    d = (d - s[1]) & MASK
    b = (b - s[0]) & MASK
    return struct.pack("<4I", a, b, c, d)


def rc6_encrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    mode_lower = mode.lower()
    if mode_lower not in ("ecb", "cbc", "ctr"):
        raise SymmetricError("不支持的 RC6 模式")

    expanded = _expand_key(key)
    payload = bytes(raw)

    if mode_lower == "ecb":
        padded = _pkcs7_pad(payload, BLOCK_BYTES)
        return b"".join(_encrypt_block(padded[i : i + BLOCK_BYTES], expanded) for i in range(0, len(padded), BLOCK_BYTES))

    if iv is None or len(iv) != BLOCK_BYTES:
        raise SymmetricError("RC6-CBC/CTR 需要 16 字节 IV")

    if mode_lower == "cbc":
        padded = _pkcs7_pad(payload, BLOCK_BYTES)
        out = bytearray()
        prev = bytes(iv)
        for i in range(0, len(padded), BLOCK_BYTES):
            block = bytes(a ^ b for a, b in zip(padded[i : i + BLOCK_BYTES], prev, strict=True))
            enc = _encrypt_block(block, expanded)
            out.extend(enc)
            prev = enc
        return bytes(out)

    counter = int.from_bytes(bytes(iv), "big")
    out = bytearray()
    for i in range(0, len(payload), BLOCK_BYTES):
        block = payload[i : i + BLOCK_BYTES]
        keystream = _encrypt_block(counter.to_bytes(BLOCK_BYTES, "big"), expanded)
        out.extend(bytes(a ^ b for a, b in zip(block, keystream[: len(block)], strict=True)))
        counter = (counter + 1) % (1 << (BLOCK_BYTES * 8))
    return bytes(out)


def rc6_decrypt(raw: bytes, key: bytes, mode: str = "ecb", iv: bytes | None = None) -> bytes:
    mode_lower = mode.lower()
    if mode_lower not in ("ecb", "cbc", "ctr"):
        raise SymmetricError("不支持的 RC6 模式")

    expanded = _expand_key(key)
    payload = bytes(raw)

    if mode_lower == "ecb":
        if len(payload) % BLOCK_BYTES != 0:
            raise SymmetricError("RC6-ECB 密文长度无效")
        plain = b"".join(_decrypt_block(payload[i : i + BLOCK_BYTES], expanded) for i in range(0, len(payload), BLOCK_BYTES))
        return _pkcs7_unpad(plain, BLOCK_BYTES)

    if iv is None or len(iv) != BLOCK_BYTES:
        raise SymmetricError("RC6-CBC/CTR 需要 16 字节 IV")

    if mode_lower == "cbc":
        if len(payload) % BLOCK_BYTES != 0:
            raise SymmetricError("RC6-CBC 密文长度无效")
        out = bytearray()
        prev = bytes(iv)
        for i in range(0, len(payload), BLOCK_BYTES):
            block = payload[i : i + BLOCK_BYTES]
            dec = _decrypt_block(block, expanded)
            out.extend(bytes(a ^ b for a, b in zip(dec, prev, strict=True)))
            prev = block
        return _pkcs7_unpad(bytes(out), BLOCK_BYTES)

    counter = int.from_bytes(bytes(iv), "big")
    out = bytearray()
    for i in range(0, len(payload), BLOCK_BYTES):
        block = payload[i : i + BLOCK_BYTES]
        keystream = _encrypt_block(counter.to_bytes(BLOCK_BYTES, "big"), expanded)
        out.extend(bytes(a ^ b for a, b in zip(block, keystream[: len(block)], strict=True)))
        counter = (counter + 1) % (1 << (BLOCK_BYTES * 8))
    return bytes(out)
