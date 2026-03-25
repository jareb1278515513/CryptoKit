"""Python API 适配层。"""

from __future__ import annotations

from cryptokit.domain.encoding import (
	EncodingError,
	base64_decode,
	base64_encode,
	utf8_decode,
	utf8_encode,
)
from cryptokit.domain.asymmetric import (
	AsymmetricError,
	ecc_generate_keypair_p160,
	ecdsa_sign_sha1,
	ecdsa_verify_sha1,
	rsa_decrypt,
	rsa_encrypt,
	rsa_generate_keypair,
	rsa_sign_sha1,
	rsa_verify_sha1,
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


def api_rsa_generate_keypair(bits: int = 1024) -> OperationResult:
	try:
		private_key_pem, public_key_pem = rsa_generate_keypair(bits=bits)
		return OperationResult.success(
			data={
				"algorithm": "rsa",
				"bits": bits,
				"private_key_pem": private_key_pem,
				"public_key_pem": public_key_pem,
			}
		)
	except (AsymmetricError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_rsa_encrypt(
	payload: str,
	*,
	public_key_pem: str,
	input_encoding: str = "utf8",
	output: str = "base64",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		cipher = rsa_encrypt(raw, public_key_pem=public_key_pem)
		return OperationResult.success(data={"algorithm": "rsa", "value": _encode_output(cipher, output)})
	except (AsymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_rsa_decrypt(
	payload: str,
	*,
	private_key_pem: str,
	input_encoding: str = "base64",
	output: str = "utf8",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		plain = rsa_decrypt(raw, private_key_pem=private_key_pem)
		value = utf8_decode(plain) if output.lower() == "utf8" else _encode_output(plain, output)
		return OperationResult.success(data={"algorithm": "rsa", "value": value})
	except (AsymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_rsa_sign_sha1(
	payload: str,
	*,
	private_key_pem: str,
	input_encoding: str = "utf8",
	output: str = "base64",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		sig = rsa_sign_sha1(raw, private_key_pem=private_key_pem)
		return OperationResult.success(data={"algorithm": "rsa-sha1", "value": _encode_output(sig, output)})
	except (AsymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_rsa_verify_sha1(
	payload: str,
	*,
	signature: str,
	public_key_pem: str,
	input_encoding: str = "utf8",
	signature_encoding: str = "base64",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		sig = _decode_input(signature, signature_encoding)
		ok = rsa_verify_sha1(raw, sig, public_key_pem=public_key_pem)
		return OperationResult.success(data={"algorithm": "rsa-sha1", "verified": ok})
	except (AsymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_ecc_generate_keypair() -> OperationResult:
	try:
		private_key_pem, public_key_pem = ecc_generate_keypair_p160()
		return OperationResult.success(
			data={
				"algorithm": "ecc-160",
				"curve": "nist-p160",
				"private_key_pem": private_key_pem,
				"public_key_pem": public_key_pem,
			}
		)
	except AsymmetricError as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_ecdsa_sign_sha1(
	payload: str,
	*,
	private_key_pem: str,
	input_encoding: str = "utf8",
	output: str = "base64",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		sig = ecdsa_sign_sha1(raw, private_key_pem=private_key_pem)
		return OperationResult.success(data={"algorithm": "ecdsa-sha1", "value": _encode_output(sig, output)})
	except (AsymmetricError, EncodingError, ValueError) as exc:
		return OperationResult.failure(StatusCode.CRYPTO_ERROR, str(exc))


def api_ecdsa_verify_sha1(
	payload: str,
	*,
	signature: str,
	public_key_pem: str,
	input_encoding: str = "utf8",
	signature_encoding: str = "base64",
) -> OperationResult:
	try:
		raw = _decode_input(payload, input_encoding)
		sig = _decode_input(signature, signature_encoding)
		ok = ecdsa_verify_sha1(raw, sig, public_key_pem=public_key_pem)
		return OperationResult.success(data={"algorithm": "ecdsa-sha1", "verified": ok})
	except (AsymmetricError, EncodingError, ValueError) as exc:
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
	"api_rsa_generate_keypair",
	"api_rsa_encrypt",
	"api_rsa_decrypt",
	"api_rsa_sign_sha1",
	"api_rsa_verify_sha1",
	"api_ecc_generate_keypair",
	"api_ecdsa_sign_sha1",
	"api_ecdsa_verify_sha1",
]
