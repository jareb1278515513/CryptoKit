"""Python API adapters."""

from __future__ import annotations

from cryptokit.domain.encoding import (
	EncodingError,
	base64_decode,
	base64_encode,
	utf8_decode,
	utf8_encode,
)
from cryptokit.domain.hash import HashError, SUPPORTED_DIGESTS, digest, hmac_digest, pbkdf2
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
	raise ValueError("output must be one of: raw, hex, base64")


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
				"encoding must be one of: hex, base64",
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


__all__ = [
	"api_utf8_encode",
	"api_utf8_decode",
	"api_base64_encode",
	"api_base64_decode",
	"api_hash_text",
	"api_hmac_text",
	"api_pbkdf2",
]
