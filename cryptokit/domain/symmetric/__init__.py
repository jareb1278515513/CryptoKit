"""对称密码领域模块导出与算法分发。"""

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
	"""按算法名分发对称加密实现。

	Args:
		raw: 明文字节串。
		key: 密钥字节串。
		algorithm: 算法名，支持 `aes`、`sm4`、`rc6`。
		mode: 分组模式。
		iv: 初始化向量。

	Returns:
		bytes: 密文字节串。

	Raises:
		SymmetricError: 算法不受支持时抛出。
	"""
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
	"""按算法名分发对称解密实现。

	Args:
		raw: 密文字节串。
		key: 密钥字节串。
		algorithm: 算法名，支持 `aes`、`sm4`、`rc6`。
		mode: 分组模式。
		iv: 初始化向量。

	Returns:
		bytes: 明文字节串。

	Raises:
		SymmetricError: 算法不受支持时抛出。
	"""
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
