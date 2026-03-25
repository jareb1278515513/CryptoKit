"""Python API 适配层。"""

from __future__ import annotations

from cryptokit.domain.encoding import (
	EncodingError,
	base64_decode,
	base64_encode,
	utf8_decode,
	utf8_encode,
)
from cryptokit.domain.hash import HashError, SUPPORTED_DIGESTS, digest, hmac_digest, pbkdf2
from cryptokit.domain.symmetric import SymmetricError, symmetric_decrypt, symmetric_encrypt
from cryptokit.shared.errors import StatusCode
from cryptokit.shared.result import OperationResult


def _encode_output(raw: bytes, output: str) -> str | bytes:
	mode = output.lower()
	if mode == "raw":
		return raw
	if mode == "hex":
		return raw.hex()
	if mode == "base64":
		return base64_encode(raw)
	raise ValueError("输出编码必须是 raw、hex 或 base64")


def _decode_input(payload: str, encoding: str) -> bytes:
	mode = encoding.lower()
	if mode == "utf8":
		return utf8_encode(payload)
	if mode == "hex":
		return bytes.fromhex(payload)
	if mode == "base64":
		return base64_decode(payload)
	raise ValueError("输入编码必须是 utf8、hex 或 base64")


def api_utf8_encode(text: str, output: str = "hex") -> OperationResult:
	try:
		raw = utf8_encode(text)
		return OperationResult.success(data={"value": _encode_output(raw, output)})
	except (EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def api_utf8_decode(hex_or_base64_payload: str, encoding: str = "hex") -> OperationResult:
	try:
		mode = encoding.lower()
		if mode == "hex":
			raw = bytes.fromhex(hex_or_base64_payload)
		elif mode == "base64":
			raw = base64_decode(hex_or_base64_payload)
		else:
			return OperationResult.failure(
				StatusCode.INVALID_INPUT,
				"解码格式必须是 hex 或 base64",
			)
		return OperationResult.success(data={"value": utf8_decode(raw)})
	except (EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def api_base64_encode(text: str) -> OperationResult:
	try:
		return OperationResult.success(data={"value": base64_encode(utf8_encode(text))})
	except EncodingError as exc:
		return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def api_base64_decode(payload: str) -> OperationResult:
	try:
		return OperationResult.success(data={"value": utf8_decode(base64_decode(payload))})
	except EncodingError as exc:
		return OperationResult.failure(StatusCode.ENCODING_ERROR, str(exc))


def api_hash_text(text: str, algorithm: str = "sha256", output: str = "hex") -> OperationResult:
	try:
		raw = digest(utf8_encode(text), algorithm)
		return OperationResult.success(
			data={
				"algorithm": algorithm.lower(),
				"supported_algorithms": sorted(SUPPORTED_DIGESTS),
				"value": _encode_output(raw, output),
			}
		)
	except (HashError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_hmac_text(
	text: str,
	key: str,
	algorithm: str = "sha256",
	output: str = "hex",
) -> OperationResult:
	try:
		raw = hmac_digest(utf8_encode(text), utf8_encode(key), algorithm)
		return OperationResult.success(
			data={
				"algorithm": algorithm.lower(),
				"value": _encode_output(raw, output),
			}
		)
	except (HashError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_pbkdf2(
	password: str,
	salt: str,
	iterations: int = 100000,
	dklen: int = 32,
	algorithm: str = "sha256",
	output: str = "hex",
) -> OperationResult:
	try:
		raw = pbkdf2(
			password=utf8_encode(password),
			salt=utf8_encode(salt),
			iterations=iterations,
			dklen=dklen,
			algorithm=algorithm,
		)
		return OperationResult.success(
			data={
				"algorithm": algorithm.lower(),
				"iterations": iterations,
				"dklen": dklen,
				"value": _encode_output(raw, output),
			}
		)
	except (HashError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_symmetric_encrypt(
	payload: str,
	*,
	algorithm: str,
	mode: str,
	key_hex: str,
	iv_hex: str | None = None,
	input_encoding: str = "utf8",
	output: str = "hex",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		key = bytes.fromhex(key_hex)
		iv = bytes.fromhex(iv_hex) if iv_hex else None
		cipher = symmetric_encrypt(raw, key=key, algorithm=algorithm, mode=mode, iv=iv)
		return OperationResult.success(
			data={
				"algorithm": algorithm.lower(),
				"mode": mode.lower(),
				"value": _encode_output(cipher, output),
			}
		)
	except (SymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_symmetric_decrypt(
	payload: str,
	*,
	algorithm: str,
	mode: str,
	key_hex: str,
	iv_hex: str | None = None,
	input_encoding: str = "hex",
	output: str = "utf8",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		key = bytes.fromhex(key_hex)
		iv = bytes.fromhex(iv_hex) if iv_hex else None
		plain = symmetric_decrypt(raw, key=key, algorithm=algorithm, mode=mode, iv=iv)
		if output.lower() == "utf8":
			value = utf8_decode(plain)
		else:
			value = _encode_output(plain, output)
		return OperationResult.success(
			data={
				"algorithm": algorithm.lower(),
				"mode": mode.lower(),
				"value": value,
			}
		)
	except (SymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


__all__ = [
	"api_utf8_encode",
	"api_utf8_decode",
	"api_base64_encode",
	"api_base64_decode",
	"api_hash_text",
	"api_hmac_text",
	"api_pbkdf2",
	"api_symmetric_encrypt",
	"api_symmetric_decrypt",
]
