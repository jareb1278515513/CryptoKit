"""Symmetric cryptography domain modules."""

from __future__ import annotations

from .aes import SymmetricError, aes_decrypt, aes_encrypt
from .rc6 import rc6_decrypt, rc6_encrypt
from .sm4 import sm4_decrypt, sm4_encrypt


def symmetric_encrypt(
	raw: bytes,
	key: bytes,
	algorithm: str,
	mode: str = "ecb",
	iv: bytes | None = None,
) -> bytes:
	algo = algorithm.lower()
	if algo == "aes":
		return aes_encrypt(raw, key=key, mode=mode, iv=iv)
	if algo == "sm4":
		return sm4_encrypt(raw, key=key, mode=mode, iv=iv)
	if algo == "rc6":
		return rc6_encrypt(raw, key=key, mode=mode, iv=iv)
	raise SymmetricError("unsupported symmetric algorithm")


def symmetric_decrypt(
	raw: bytes,
	key: bytes,
	algorithm: str,
	mode: str = "ecb",
	iv: bytes | None = None,
) -> bytes:
	algo = algorithm.lower()
	if algo == "aes":
		return aes_decrypt(raw, key=key, mode=mode, iv=iv)
	if algo == "sm4":
		return sm4_decrypt(raw, key=key, mode=mode, iv=iv)
	if algo == "rc6":
		return rc6_decrypt(raw, key=key, mode=mode, iv=iv)
	raise SymmetricError("unsupported symmetric algorithm")


__all__ = [
	"SymmetricError",
	"aes_encrypt",
	"aes_decrypt",
	"sm4_encrypt",
	"sm4_decrypt",
	"rc6_encrypt",
	"rc6_decrypt",
	"symmetric_encrypt",
	"symmetric_decrypt",
]
